from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from reposentinel.config import Settings


class GitHubError(RuntimeError):
    """Base class for safe, user-facing GitHub API failures."""


class MissingCredentialsError(GitHubError):
    pass


class AuthenticationError(GitHubError):
    pass


class RateLimitError(GitHubError):
    pass


class NetworkError(GitHubError):
    pass


class APIResponseError(GitHubError):
    pass


@dataclass(frozen=True)
class GitHubRepository:
    full_name: str
    default_branch: str | None
    description: str | None
    private: bool

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "GitHubRepository":
        full_name = payload.get("full_name")
        if not isinstance(full_name, str) or "/" not in full_name:
            raise APIResponseError("GitHub returned a repository without a valid full_name")
        return cls(
            full_name=full_name.lower(),
            default_branch=payload.get("default_branch") if isinstance(payload.get("default_branch"), str) else None,
            description=payload.get("description") if isinstance(payload.get("description"), str) else None,
            private=bool(payload.get("private", False)),
        )


@dataclass(frozen=True)
class GitHubTreeEntry:
    path: str
    sha: str
    size: int


class GitHubClient:
    """Read-only GitHub REST client. It never logs or exposes the token."""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        token = settings.github_token.get_secret_value() if settings.github_token else ""
        if not token:
            raise MissingCredentialsError("REPOSENTINEL_GITHUB_TOKEN is not configured")
        self.base_url = settings.github_api_url
        self.timeout = settings.github_timeout_seconds
        self.transport = transport
        self._headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            with httpx.Client(transport=self.transport, headers=self._headers, base_url=self.base_url) as client:
                response = client.request(method, path, timeout=self.timeout, **kwargs)
        except (httpx.HTTPError, OSError) as error:
            raise NetworkError("GitHub network request failed") from error
        if response.status_code in {401, 403}:
            if response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0":
                raise RateLimitError("GitHub API rate limit reached; try again later")
            raise AuthenticationError("GitHub rejected the configured token")
        if response.status_code == 429:
            raise RateLimitError("GitHub API rate limit reached; try again later")
        if response.status_code >= 400:
            raise APIResponseError(f"GitHub API returned HTTP {response.status_code}")
        return response

    @staticmethod
    def _json(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError as error:
            raise APIResponseError("GitHub returned malformed JSON") from error

    def list_repositories(self) -> list[GitHubRepository]:
        repositories: list[GitHubRepository] = []
        page = 1
        while True:
            response = self._request("GET", "/user/repos", params={"per_page": 100, "page": page, "sort": "full_name"})
            payload = self._json(response)
            if not isinstance(payload, list):
                raise APIResponseError("GitHub returned an invalid repository list")
            repositories.extend(GitHubRepository.from_json(item) for item in payload if isinstance(item, dict))
            if len(payload) < 100 or "rel=\"next\"" not in response.headers.get("link", ""):
                return repositories
            page += 1

    def get_repository(self, full_name: str) -> GitHubRepository:
        owner, repo = _split_full_name(full_name)
        response = self._request("GET", f"/repos/{quote(owner)}/{quote(repo)}")
        payload = self._json(response)
        if not isinstance(payload, dict):
            raise APIResponseError("GitHub returned invalid repository metadata")
        return GitHubRepository.from_json(payload)

    def get_default_branch_sha(self, repository: GitHubRepository) -> str:
        if not repository.default_branch:
            raise APIResponseError("GitHub repository has no default branch")
        owner, repo = _split_full_name(repository.full_name)
        response = self._request(
            "GET", f"/repos/{quote(owner)}/{quote(repo)}/branches/{quote(repository.default_branch)}"
        )
        payload = self._json(response)
        sha = payload.get("commit", {}).get("sha") if isinstance(payload, dict) else None
        if not isinstance(sha, str) or not sha:
            raise APIResponseError("GitHub returned no commit SHA for the default branch")
        return sha

    def list_source_files(self, full_name: str, commit_sha: str, extensions: list[str]) -> tuple[list[GitHubTreeEntry], bool]:
        owner, repo = _split_full_name(full_name)
        response = self._request(
            "GET", f"/repos/{quote(owner)}/{quote(repo)}/git/trees/{quote(commit_sha)}", params={"recursive": "1"}
        )
        payload = self._json(response)
        if not isinstance(payload, dict) or not isinstance(payload.get("tree"), list):
            raise APIResponseError("GitHub returned an invalid repository tree")
        entries: list[GitHubTreeEntry] = []
        for item in payload["tree"]:
            if not isinstance(item, dict) or item.get("type") != "blob" or not isinstance(item.get("path"), str):
                continue
            path = item["path"]
            if any(path.lower().endswith(extension.lower()) for extension in extensions):
                entries.append(GitHubTreeEntry(path, str(item.get("sha", "")), int(item.get("size", 0) or 0)))
        return entries, bool(payload.get("truncated", False))

    def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
        owner, repo = _split_full_name(full_name)
        encoded_path = "/".join(quote(part) for part in path.split("/"))
        response = self._request("GET", f"/repos/{quote(owner)}/{quote(repo)}/contents/{encoded_path}", params={"ref": commit_sha})
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
            raise APIResponseError(f"GitHub returned unsupported content for {path}")
        try:
            encoded = "".join(payload["content"].split())
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise APIResponseError(f"GitHub returned non-UTF-8 or malformed content for {path}") from error


def _split_full_name(full_name: str) -> tuple[str, str]:
    parts = full_name.strip().split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("Repository must be in OWNER/REPO form")
    return parts[0], parts[1]
