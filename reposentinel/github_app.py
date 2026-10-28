from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any
from urllib.parse import quote

import httpx

from reposentinel.config import Settings
import threading
from datetime import datetime
from typing import Any, Callable
import jwt


logger = logging.getLogger(__name__)


class GitHubAppError(RuntimeError):
    def __init__(self, message: str, *, code: str = "GITHUB_APP_ERROR", status_code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class InstallationRepository:
    github_repo_id: int
    full_name: str
    default_branch: str | None
    description: str | None
    private: bool


@dataclass(frozen=True)
class InstallationInfo:
    github_installation_id: int
    account_login: str
    account_type: str
    permissions: dict[str, str]


def issue_installation_state(user_id: str, secret: str, *, now: int | None = None) -> str:
    issued = int(time.time()) if now is None else now
    payload = {"user_id": user_id, "issued_at": issued, "nonce": secrets_token()}
    encoded = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def verify_installation_state(state: str, user_id: str, secret: str, *, now: int | None = None) -> bool:
    try:
        encoded, signature = state.split(".", 1)
        expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        current = int(time.time()) if now is None else now
        if not isinstance(payload, dict):
            return False
        return payload.get("user_id") == user_id and 0 <= current - int(payload["issued_at"]) <= 600
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def installation_state_nonce(state: str) -> str:
    encoded, _ = state.split(".", 1)
    payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    if not isinstance(payload, dict):
        raise ValueError("state payload is invalid")
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("state nonce is missing")
    return nonce


def installation_state_user_id(state: str, secret: str, now: int | None = None) -> str | None:
    try:
        encoded, _ = state.split(".", 1)
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if not isinstance(payload, dict):
            return None
        user_id = payload.get("user_id")
        return str(user_id) if isinstance(user_id, str) and verify_installation_state(state, user_id, secret, now=now) else None
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError):
        return None


def secrets_token() -> str:
    # Imported locally to keep the state helpers' cryptographic inputs explicit.
    import secrets
    return secrets.token_urlsafe(18)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class GitHubAppClient:
    def _private_key(self) -> str:
        configured = getattr(self.settings, "github_app_private_key", None)
        if configured:
            key = configured.get_secret_value()
        else:
            path = getattr(self.settings, "github_app_private_key_path", None)
            if not path:
                raise GitHubAppError("GitHub App credentials are not configured")
            try:
                key = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise GitHubAppError("GitHub App private key could not be read") from exc
        if not key.strip() or len(key) > 200_000:
            raise GitHubAppError("GitHub App private key is invalid")
        return key

    def _app_jwt(self, now: int | None = None) -> str:
        app_id = getattr(self.settings, "github_app_id", None)
        if not app_id:
            raise GitHubAppError("GitHub App ID is not configured")
        current = int(now if now is not None else self._clock())
        try:
            return str(jwt.encode({"iat": current - 60, "exp": current + 540, "iss": str(app_id)}, self._private_key(), algorithm="RS256"))
        except (jwt.PyJWTError, ValueError, TypeError) as exc:
            raise GitHubAppError("GitHub App private key is invalid") from exc

    def _installation_token(self, installation_id: int, force_refresh: bool = False) -> str:
        static = getattr(self, "_static_token", None) or getattr(self, "installation_token", None) or getattr(self, "token", None)
        if static:
            return static
        with self._token_lock:
            cached = self._token_cache.get(installation_id)
            skew = getattr(self.settings, "github_app_token_skew_seconds", 60)
            if not force_refresh and cached and cached[1] - skew > self._clock():
                return cached[0]
            response = self._raw_request("POST", f"/app/installations/{installation_id}/access_tokens", {"Authorization": f"Bearer {self._app_jwt()}"})
            if response.status_code == 401:
                raise GitHubAppError("GitHub App credentials were rejected", code="GITHUB_APP_CREDENTIALS_REJECTED", status_code=502)
            if response.status_code == 403:
                raise GitHubAppError("GitHub App installation access was denied", code="GITHUB_PERMISSION_DENIED", status_code=403)
            if response.status_code == 404:
                raise GitHubAppError("GitHub installation is revoked or unavailable", code="GITHUB_INSTALLATION_REVOKED", status_code=404)
            if response.status_code >= 400:
                raise GitHubAppError("GitHub installation token exchange failed", code="GITHUB_TOKEN_EXCHANGE_FAILED", status_code=502)
            try:
                body = response.json()
                token = body["token"]
                expiry = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00")).timestamp()
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                raise GitHubAppError("GitHub returned an invalid installation token response") from exc
            if not isinstance(token, str) or not token or expiry <= self._clock():
                raise GitHubAppError("GitHub returned an expired installation token")
            self._token_cache[installation_id] = (token, expiry)
            return token

    def _raw_request(self, method: str, path: str, headers: dict[str, str], params: dict[str, Any] | None = None) -> httpx.Response:
        retries = getattr(self.settings, "github_app_max_retries", 2)
        delay = getattr(self.settings, "github_app_retry_backoff_seconds", 0.5)
        for attempt in range(retries + 1):
            try:
                with httpx.Client(base_url=self.base_url, transport=self.transport, timeout=self.settings.github_timeout_seconds) as client:
                    response = client.request(method, path, headers=headers, params=params)
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt >= retries:
                    raise GitHubAppError("GitHub API network request failed") from exc
                time.sleep(delay * (2**attempt))
                continue
            if response.status_code not in (429,) and not 500 <= response.status_code <= 599:
                return response
            if attempt >= retries:
                return response
            time.sleep(delay * (2**attempt))
        raise GitHubAppError("GitHub API request failed")

    @staticmethod
    def _json_object(response: httpx.Response) -> dict[str, Any]:
        try:
            value = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise GitHubAppError("GitHub API returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise GitHubAppError("GitHub API returned an invalid response")
        return value

    def _installation_request(self, method: str, path: str, installation_id: int, params: dict[str, Any] | None = None) -> httpx.Response:
        for refresh in (False, True):
            token = self._installation_token(installation_id, force_refresh=refresh)
            response = self._raw_request(method, path, {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"}, params)
            if response.status_code != 401:
                return response
            with self._token_lock:
                self._token_cache.pop(installation_id, None)
        return response

    def is_user_authorized(self, installation_id: int, user_id: str) -> bool:
        resolver = getattr(self, "user_token_resolver", None)
        if resolver is None:
            return False
        user_token = resolver(user_id)
        if not user_token:
            return False
        response = self._raw_request(
            "GET",
            f"/user/installations/{installation_id}",
            {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {user_token}"},
        )
        if response.status_code in {401, 403, 404}:
            return False
        if response.status_code >= 400:
            raise GitHubAppError("GitHub user authorization check failed")
        return True

    def list_user_installations(self, user_id: str) -> list[int]:
        """Find this App's installations visible to the connected GitHub user."""
        returned_count = 0
        matching_count = 0

        def log_discovery(*, token_present: bool, status_code: int | None, error_code: str | None = None) -> None:
            message = (
                "github installation discovery token_present=%s status=%s "
                "installations_returned=%s app_id_matches=%s"
            )
            values: tuple[object, ...] = (token_present, status_code, returned_count, matching_count)
            if error_code:
                logger.warning(message + " error_code=%s", *values, error_code)
            else:
                logger.info(message, *values)

        app_client_id = getattr(self.settings, "github_app_client_id", None)
        app_client_credential = getattr(self.settings, "github_app_client_credential", None)
        app_redirect_uri = getattr(self.settings, "github_app_oauth_redirect_uri", None)
        if not app_client_id or not app_client_credential or not app_redirect_uri:
            log_discovery(token_present=False, status_code=None, error_code="GITHUB_APP_USER_AUTH_NOT_CONFIGURED")
            raise GitHubAppError(
                "GitHub App user authorization is not configured; an OAuth App token cannot list App installations",
                code="GITHUB_APP_USER_AUTH_NOT_CONFIGURED",
                status_code=503,
            )
        resolver = getattr(self, "user_token_resolver", None)
        user_token = resolver(user_id) if resolver else None
        if not user_token:
            log_discovery(token_present=False, status_code=None, error_code="GITHUB_OAUTH_TOKEN_MISSING")
            raise GitHubAppError("GitHub user identity is not connected", code="GITHUB_OAUTH_TOKEN_MISSING", status_code=401)

        installations: list[int] = []
        page = 1
        app_slug = (getattr(self.settings, "github_app_slug", None) or "").lower()
        app_id = getattr(self.settings, "github_app_id", None)
        saw_installation = False
        while True:
            try:
                response = self._raw_request(
                    "GET", "/user/installations",
                    {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {user_token}"},
                    {"per_page": 100, "page": page},
                )
            except GitHubAppError as error:
                log_discovery(token_present=True, status_code=None, error_code=error.code)
                raise
            if response.status_code == 401:
                log_discovery(token_present=True, status_code=401, error_code="GITHUB_OAUTH_REVOKED")
                raise GitHubAppError("GitHub user authorization was rejected", code="GITHUB_OAUTH_REVOKED", status_code=401)
            if response.status_code == 403:
                log_discovery(token_present=True, status_code=403, error_code="GITHUB_PERMISSION_DENIED")
                raise GitHubAppError("GitHub user is not permitted to list installations", code="GITHUB_PERMISSION_DENIED", status_code=403)
            if response.status_code == 429:
                log_discovery(token_present=True, status_code=429, error_code="GITHUB_RATE_LIMITED")
                raise GitHubAppError("GitHub installation discovery was rate limited", code="GITHUB_RATE_LIMITED", status_code=429)
            if response.status_code >= 400:
                log_discovery(token_present=True, status_code=response.status_code, error_code="GITHUB_INSTALLATION_DISCOVERY_FAILED")
                raise GitHubAppError("GitHub installation discovery failed", code="GITHUB_INSTALLATION_DISCOVERY_FAILED", status_code=502)
            payload = self._json_object(response)
            items = payload.get("installations")
            if not isinstance(items, list):
                log_discovery(token_present=True, status_code=response.status_code, error_code="GITHUB_INVALID_INSTALLATION_RESPONSE")
                raise GitHubAppError("GitHub returned an invalid installation list")
            returned_count += len(items)
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("id"), int):
                    log_discovery(token_present=True, status_code=response.status_code, error_code="GITHUB_INVALID_INSTALLATION_RESPONSE")
                    raise GitHubAppError("GitHub returned an invalid installation record")
                saw_installation = True
                app_matches = (
                    app_id is not None and item.get("app_id") == app_id
                ) or (
                    app_id is None and app_slug and str(item.get("app_slug", "")).lower() == app_slug
                )
                if app_matches:
                    installations.append(item["id"])
                    matching_count += 1
            log_discovery(token_present=True, status_code=response.status_code)
            if len(items) < 100 and 'rel="next"' not in response.headers.get("link", ""):
                if installations:
                    return installations
                if saw_installation:
                    log_discovery(token_present=True, status_code=response.status_code, error_code="GITHUB_APP_NOT_ACCESSIBLE")
                    raise GitHubAppError("The connected GitHub user can access installations, but not the configured App", code="GITHUB_APP_NOT_ACCESSIBLE", status_code=403)
                log_discovery(token_present=True, status_code=response.status_code, error_code="GITHUB_APP_NOT_INSTALLED")
                raise GitHubAppError("No GitHub App installation is accessible to the connected user", code="GITHUB_APP_NOT_INSTALLED", status_code=404)
            page += 1

    """Read-only installation repository client; token acquisition is injected/configured separately."""

    def __init__(self, settings: Settings, *, installation_token: str | None = None,
                 transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], float] | None = None,
                 user_token_resolver: Callable[[str], str | None] | None = None) -> None:
        if not installation_token and not getattr(settings, "github_app_id", None):
            raise GitHubAppError("GitHub App installation token is not configured")
        self.settings = settings
        self._clock = clock or time.time
        self.user_token_resolver = user_token_resolver
        self.base_url = settings.github_api_url
        self.token = installation_token
        self.transport = transport
        self._token_cache: dict[int, tuple[str, float]] = {}
        self._token_lock = threading.RLock()

    def get_installation(self, installation_id: int) -> InstallationInfo:
        if not self.token:
            response = self._raw_request("GET", f"/app/installations/{installation_id}", {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self._app_jwt()}"})
            if response.status_code == 404:
                raise GitHubAppError("GitHub installation is revoked or unavailable")
            if response.status_code in {401, 403}:
                raise GitHubAppError("GitHub App authorization was rejected")
            if response.status_code >= 400:
                raise GitHubAppError("GitHub App installation lookup failed")
            payload = self._json_object(response)
            account = payload.get("account")
            if not isinstance(account, dict) or not isinstance(account.get("login"), str):
                raise GitHubAppError("GitHub App returned an invalid installation record")
            permissions = payload.get("permissions") if isinstance(payload.get("permissions"), dict) else {}
            return InstallationInfo(installation_id, account["login"], str(account.get("type", "Unknown")), {str(k): str(v) for k, v in permissions.items()})
        try:
            with httpx.Client(transport=self.transport, base_url=self.base_url, headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
            }) as client:
                response = client.get(f"/app/installations/{quote(str(installation_id))}", timeout=30.0)
        except (httpx.HTTPError, OSError) as error:
            raise GitHubAppError("GitHub App installation request failed") from error
        if response.status_code in {401, 403}:
            raise GitHubAppError("GitHub App authorization was rejected")
        if response.status_code >= 400:
            raise GitHubAppError(f"GitHub App API returned HTTP {response.status_code}")
        try:
            payload: Any = response.json()
        except ValueError as error:
            raise GitHubAppError("GitHub App returned malformed installation JSON") from error
        account = payload.get("account") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or not isinstance(account, dict) or not isinstance(account.get("login"), str):
            raise GitHubAppError("GitHub App returned an invalid installation record")
        return InstallationInfo(
            github_installation_id=installation_id,
            account_login=account["login"],
            account_type=str(account.get("type", "Unknown")),
            permissions=payload.get("permissions", {}) if isinstance(payload.get("permissions", {}), dict) else {},
        )

    def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]:
        if not self.token:
            repositories: list[InstallationRepository] = []
            page = 1
            while True:
                response = self._installation_request("GET", "/installation/repositories", installation_id, {"per_page": 100, "page": page})
                if response.status_code == 404:
                    raise GitHubAppError("GitHub installation is revoked or unavailable", code="GITHUB_INSTALLATION_REVOKED", status_code=404)
                if response.status_code == 403:
                    raise GitHubAppError("GitHub installation access was denied", code="GITHUB_PERMISSION_DENIED", status_code=403)
                if response.status_code >= 400:
                    raise GitHubAppError("GitHub App repository request failed", code="GITHUB_REPOSITORY_FETCH_FAILED", status_code=502)
                payload = self._json_object(response)
                items = payload.get("repositories")
                if not isinstance(items, list):
                    raise GitHubAppError("GitHub App returned an invalid repository list")
                for item in items:
                    if not isinstance(item, dict) or not isinstance(item.get("id"), int) or not isinstance(item.get("full_name"), str):
                        raise GitHubAppError("GitHub App returned an invalid repository record")
                    repositories.append(InstallationRepository(item["id"], item["full_name"].lower(), item.get("default_branch"), item.get("description"), bool(item.get("private", False))))
                if 'rel="next"' not in response.headers.get("link", ""):
                    return repositories
                page += 1
        repositories: list[InstallationRepository] = []
        page = 1
        while True:
            try:
                with httpx.Client(transport=self.transport, base_url=self.base_url, headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {self.token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                }) as client:
                    response = client.get(
                        f"/user/installations/{quote(str(installation_id))}/repositories",
                        params={"per_page": 100, "page": page}, timeout=30.0,
                    )
            except (httpx.HTTPError, OSError) as error:
                raise GitHubAppError("GitHub App repository request failed") from error
            if response.status_code in {401, 403}:
                raise GitHubAppError("GitHub App authorization was rejected")
            if response.status_code >= 400:
                raise GitHubAppError(f"GitHub App API returned HTTP {response.status_code}")
            try:
                payload: Any = response.json()
            except ValueError as error:
                raise GitHubAppError("GitHub App returned malformed JSON") from error
            items = payload.get("repositories") if isinstance(payload, dict) else None
            if not isinstance(items, list):
                raise GitHubAppError("GitHub App returned an invalid repository list")
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("id"), int) or not isinstance(item.get("full_name"), str):
                    raise GitHubAppError("GitHub App returned an invalid repository record")
                repositories.append(InstallationRepository(
                    github_repo_id=item["id"], full_name=item["full_name"].lower(),
                    default_branch=item.get("default_branch") if isinstance(item.get("default_branch"), str) else None,
                    description=item.get("description") if isinstance(item.get("description"), str) else None,
                    private=bool(item.get("private", False)),
                ))
            if len(items) < 100 or "rel=\"next\"" not in response.headers.get("link", ""):
                return repositories
            page += 1
