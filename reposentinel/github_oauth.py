from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlencode

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.github_app import installation_state_nonce, issue_installation_state, verify_installation_state


class GitHubOAuthError(RuntimeError):
    """Safe OAuth integration error; credential values are never included."""

    def __init__(self, message: str, *, code: str = "GITHUB_OAUTH_ERROR") -> None:
        super().__init__(message)
        self.code = code


def oauth_state(local_user_id: str, state_key: str) -> str:
    return issue_installation_state(local_user_id, state_key)


def oauth_state_nonce(state: str) -> str:
    return installation_state_nonce(state)


def verify_oauth_state(state: str, state_key: str, now: int | None = None) -> bool:
    try:
        encoded, _ = state.split(".", 1)
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if not isinstance(payload, dict):
            return False
        user_id = payload.get("user_id")
        return isinstance(user_id, str) and verify_installation_state(state, user_id, state_key, now=now)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError):
        return False


@dataclass(frozen=True)
class GitHubIdentity:
    github_user_id: int
    login: str


def _decode_key(value: str) -> bytes:
    try:
        key = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeError):
        key = value.encode("utf-8")
    if len(key) not in {16, 24, 32}:
        raise GitHubOAuthError("GitHub token encryption key is invalid", code="GITHUB_TOKEN_ENCRYPTION_KEY_INVALID")
    return key


class TokenCipher:
    def __init__(self, encoded_key: str) -> None:
        self._key = _decode_key(encoded_key)

    def encrypt(self, token: str) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, token.encode("utf-8"), None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> str:
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext, None).decode("utf-8")
        except Exception as exc:
            raise GitHubOAuthError("Stored GitHub credential could not be decrypted", code="GITHUB_TOKEN_DECRYPTION_FAILED") from exc


class GitHubTokenStore:
    def __init__(self, database: Database, cipher: TokenCipher) -> None:
        self.database = database
        self.cipher = cipher

    def ensure_schema(self) -> None:
        with self.database.connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS github_oauth_states (
                    nonce TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id),
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS github_identities (
                    local_user_id TEXT PRIMARY KEY REFERENCES users(id),
                    github_user_id INTEGER NOT NULL UNIQUE,
                    github_login TEXT NOT NULL,
                    encrypted_token BLOB NOT NULL,
                    token_nonce BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

    def store_state(self, nonce: str, local_user_id: str, expires_at: str) -> None:
        with self.database.connection() as connection:
            connection.execute("INSERT INTO github_oauth_states(nonce, user_id, expires_at) VALUES (?, ?, ?)", (nonce, local_user_id, expires_at))

    def consume_state(self, nonce: str) -> str | None:
        with self.database.connection() as connection:
            now = datetime.now(timezone.utc).isoformat()
            row = connection.execute("SELECT user_id FROM github_oauth_states WHERE nonce = ? AND consumed_at IS NULL AND expires_at > ?", (nonce, now)).fetchone()
            if row is None:
                return None
            updated = connection.execute("UPDATE github_oauth_states SET consumed_at = ? WHERE nonce = ? AND consumed_at IS NULL", (now, nonce)).rowcount
            return str(row[0]) if updated == 1 else None

    def save(self, local_user_id: str, identity: GitHubIdentity, token: str) -> None:
        nonce, ciphertext = self.cipher.encrypt(token)
        now = datetime.now(timezone.utc).isoformat()
        with self.database.connection() as connection:
            try:
                connection.execute("""INSERT INTO github_identities(local_user_id, github_user_id, github_login, encrypted_token, token_nonce, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(local_user_id) DO UPDATE SET github_user_id=excluded.github_user_id, github_login=excluded.github_login, encrypted_token=excluded.encrypted_token, token_nonce=excluded.token_nonce, updated_at=excluded.updated_at""", (local_user_id, identity.github_user_id, identity.login, ciphertext, nonce, now, now))
            except Exception as exc:
                raise GitHubOAuthError("GitHub identity is already linked to another user") from exc

    def get_token(self, local_user_id: str) -> str | None:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM github_identities WHERE local_user_id = ?", (local_user_id,)).fetchone()
        if row is None:
            return None
        try:
            return self.cipher.decrypt(bytes(row["token_nonce"]), bytes(row["encrypted_token"]))
        except GitHubOAuthError:
            return None

    def get_identity(self, local_user_id: str) -> GitHubIdentity | None:
        """Return display identity metadata without decrypting the OAuth token."""
        with self.database.connection() as connection:
            row = connection.execute(
                "SELECT github_user_id, github_login FROM github_identities "
                "WHERE local_user_id = ?",
                (local_user_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            return GitHubIdentity(int(row["github_user_id"]), str(row["github_login"]))
        except (TypeError, ValueError):
            return None


class GitHubOAuthClient:
    def __init__(self, settings: Settings, *, transport: httpx.BaseTransport | None = None, clock: Callable[[], float] | None = None) -> None:
        self.settings = settings
        self.transport = transport
        self.clock = clock or time.time

    def _client_credentials(self) -> tuple[str | None, str | None, bool]:
        """Return client credentials and whether they belong to the GitHub App."""
        app_client_id = self.settings.github_app_client_id
        app_credential = getattr(self.settings, "github_app_client_credential", None)
        if app_client_id or app_credential:
            return (
                app_client_id,
                app_credential.get_secret_value() if app_credential else None,
                True,
            )
        credential = self.settings.github_oauth_client_credential
        return (
            self.settings.github_oauth_client_id,
            credential.get_secret_value() if credential else None,
            False,
        )

    def authorization_url(self, state: str) -> str:
        client_id, _, is_github_app = self._client_credentials()
        redirect_uri = self.settings.github_app_oauth_redirect_uri if is_github_app else self.settings.github_oauth_redirect_uri
        if not client_id or not redirect_uri:
            raise GitHubOAuthError("GitHub OAuth is not configured", code="GITHUB_OAUTH_NOT_CONFIGURED")
        query_values = {"client_id": client_id, "redirect_uri": redirect_uri, "state": state}
        if not is_github_app:
            query_values["scope"] = "read:user"
        query = urlencode(query_values)
        return f"{self.settings.github_oauth_url.rstrip('/')}/login/oauth/authorize?{query}"

    def _request(self, method: str, url: str, *, headers: dict[str, str], data: dict[str, str] | None = None) -> httpx.Response:
        attempts = self.settings.github_app_max_retries + 1
        for attempt in range(attempts):
            try:
                with httpx.Client(transport=self.transport, timeout=self.settings.github_timeout_seconds) as client:
                    response = client.request(method, url, headers=headers, data=data)
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt >= self.settings.github_app_max_retries:
                    raise GitHubOAuthError("GitHub OAuth network request failed", code="GITHUB_OAUTH_NETWORK_ERROR") from exc
                continue
            if response.status_code != 429 and not 500 <= response.status_code <= 599:
                return response
            if attempt >= self.settings.github_app_max_retries:
                return response
        raise GitHubOAuthError("GitHub OAuth request failed", code="GITHUB_OAUTH_REQUEST_FAILED")

    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        try:
            value = response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise GitHubOAuthError("GitHub OAuth returned malformed JSON", code="GITHUB_OAUTH_INVALID_JSON") from exc
        if not isinstance(value, dict):
            raise GitHubOAuthError("GitHub OAuth returned an invalid response", code="GITHUB_OAUTH_INVALID_RESPONSE")
        return value

    def exchange_code(self, code: str) -> str:
        client_id, client_secret, is_github_app = self._client_credentials()
        redirect_uri = self.settings.github_app_oauth_redirect_uri if is_github_app else self.settings.github_oauth_redirect_uri
        if not client_id or not client_secret or not redirect_uri:
            raise GitHubOAuthError("GitHub OAuth is not configured", code="GITHUB_OAUTH_NOT_CONFIGURED")
        response = self._request(
            "POST",
            f"{self.settings.github_oauth_url.rstrip('/')}/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={"client_id": client_id, "client_secret": client_secret, "code": code, "redirect_uri": redirect_uri},
        )
        if response.status_code >= 400:
            raise GitHubOAuthError("GitHub authorization code exchange failed", code="GITHUB_AUTH_CODE_EXCHANGE_FAILED")
        token = self._json(response).get("access_token")
        if not isinstance(token, str) or not token:
            raise GitHubOAuthError("GitHub authorization code exchange returned no token", code="GITHUB_AUTH_TOKEN_MISSING")
        return token

    def authenticated_identity(self, token: str) -> GitHubIdentity:
        response = self._request("GET", f"{self.settings.github_api_url.rstrip('/')}/user", headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"})
        if response.status_code in {401, 403}:
            raise GitHubOAuthError("GitHub user authorization was rejected", code="GITHUB_USER_AUTH_REJECTED")
        if response.status_code >= 400:
            raise GitHubOAuthError("GitHub user lookup failed", code="GITHUB_USER_LOOKUP_FAILED")
        body = self._json(response)
        if not isinstance(body.get("id"), int) or not isinstance(body.get("login"), str):
            raise GitHubOAuthError("GitHub user response is invalid", code="GITHUB_USER_RESPONSE_INVALID")
        return GitHubIdentity(body["id"], body["login"])
