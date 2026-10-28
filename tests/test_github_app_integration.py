import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from pydantic import SecretStr

from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.auth_api import create_app
from reposentinel.github_app import GitHubAppClient, GitHubAppError, InstallationInfo, InstallationRepository, issue_installation_state, verify_installation_state


def app_key() -> tuple[str, str]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_text = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    public_text = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return private_text, public_text


class GitHubAppIntegrationTests(unittest.TestCase):
    def test_callback_state_is_one_time_and_future_state_is_invalid(self) -> None:
        self.assertFalse(verify_installation_state(issue_installation_state("u", "k", now=100), "u", "k", now=99))

        class Provider:
            def is_user_authorized(self, installation_id: int, user_id: str) -> bool:
                return True

            def get_installation(self, installation_id: int) -> InstallationInfo:
                return InstallationInfo(installation_id, "acme", "Organization", {"contents": "read"})

            def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]:
                return [InstallationRepository(7, "acme/demo", "main", None, True)]

        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(database_path=Path(directory) / "state.db", github_app_slug="demo", github_app_state_key=SecretStr("state-key"))
            client = TestClient(create_app(settings=settings, github_app=Provider()))
            registration = client.post("/api/v1/auth/register", json={"email": "a@example.com", "password": "long-test-password"})
            headers = {"Authorization": f"Bearer {registration.json()['access_token']}"}
            start = client.get("/api/v1/github/installations/start", headers=headers)
            state = parse_qs(urlsplit(start.json()["install_url"]).query)["state"][0]
            self.assertEqual(client.post("/api/v1/github/installations/callback", params={"state": state, "installation_id": 11}, headers=headers).status_code, 200)
            self.assertEqual(client.post("/api/v1/github/installations/callback", params={"state": state, "installation_id": 11}, headers=headers).status_code, 400)

    def test_jwt_claims_and_invalid_key(self) -> None:
        private, public = app_key()
        settings = Settings(github_app_id=123, github_app_private_key=SecretStr(private))
        client = GitHubAppClient(settings, clock=lambda: 1_700_000_000)
        token = client._app_jwt()
        claims = jwt.decode(token, public, algorithms=["RS256"], options={"verify_iat": False, "verify_exp": False})
        self.assertEqual(claims["iss"], "123")
        self.assertEqual(claims["exp"] - claims["iat"], 600)
        with self.assertRaises(GitHubAppError):
            GitHubAppClient(Settings(github_app_id=123, github_app_private_key=SecretStr("not-a-key")))._app_jwt()

    def test_exchange_is_cached_and_refreshes_expired_response(self) -> None:
        private, _ = app_key()
        now = [1_700_000_000.0]
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.method == "POST":
                expiry = "2023-11-14T23:00:00Z" if len(calls) == 1 else "2023-11-15T01:00:00Z"
                return httpx.Response(201, json={"token": f"installation-{len(calls)}", "expires_at": expiry})
            return httpx.Response(200, json={"repositories": []})

        settings = Settings(github_app_id=123, github_app_private_key=SecretStr(private), github_app_token_skew_seconds=1, github_app_retry_backoff_seconds=0)
        client = GitHubAppClient(settings, transport=httpx.MockTransport(handler), clock=lambda: now[0])
        self.assertEqual(client._installation_token(42), "installation-1")
        self.assertEqual(client._installation_token(42), "installation-1")
        self.assertEqual(calls.count("/app/installations/42/access_tokens"), 1)
        now[0] = 1_700_003_000.0
        self.assertEqual(client._installation_token(42), "installation-2")
        self.assertEqual(calls.count("/app/installations/42/access_tokens"), 2)

    def test_retryable_http_failure_and_revoked_installation(self) -> None:
        private, _ = app_key()
        responses = [httpx.Response(503), httpx.Response(404)]

        def handler(request: httpx.Request) -> httpx.Response:
            return responses.pop(0)

        settings = Settings(github_app_id=123, github_app_private_key=SecretStr(private), github_app_max_retries=1, github_app_retry_backoff_seconds=0)
        client = GitHubAppClient(settings, transport=httpx.MockTransport(handler))
        with self.assertRaises(GitHubAppError) as context:
            client._installation_token(42)
        self.assertIn("revoked", str(context.exception))

    def test_user_authorization_uses_resolved_token_and_fails_closed(self) -> None:
        observed: list[tuple[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            observed.append((request.url.path, request.headers["Authorization"]))
            return httpx.Response(200, json={"id": 42})

        settings = Settings(github_app_id=123, github_app_private_key=SecretStr("unused"), github_app_retry_backoff_seconds=0)
        client = GitHubAppClient(settings, transport=httpx.MockTransport(handler), user_token_resolver=lambda user_id: "github-user-token")
        self.assertTrue(client.is_user_authorized(42, "local-user"))
        self.assertEqual(observed[0][0], "/user/installations/42")
        self.assertEqual(observed[0][1], "Bearer github-user-token")
        self.assertFalse(GitHubAppClient(settings, transport=httpx.MockTransport(lambda request: httpx.Response(403))).is_user_authorized(42, "local-user"))

    def test_user_installation_discovery_is_paginated_and_app_scoped(self) -> None:
        private, _ = app_key()
        pages: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/user/installations")
            page = int(request.url.params.get("page", "1"))
            pages.append(page)
            if page == 1:
                items = [{"id": index, "app_id": 999, "app_slug": "other-app"} for index in range(1, 100)]
                items.append({"id": 501, "app_id": 123, "app_slug": "sentraforge-test"})
                return httpx.Response(200, json={"installations": items}, headers={"link": "<https://api.github.com/user/installations?page=2>; rel=\"next\""})
            return httpx.Response(200, json={"installations": [{"id": 502, "app_id": 123, "app_slug": "sentraforge-test"}]})

        settings = Settings(
            github_app_id=123,
            github_app_private_key=SecretStr(private),
            github_app_slug="sentraforge-test",
            github_app_client_id="app-client",
            github_app_client_credential="app-secret",
            github_app_oauth_redirect_uri="http://localhost/callback",
            github_app_retry_backoff_seconds=0,
        )
        client = GitHubAppClient(
            settings,
            transport=httpx.MockTransport(handler),
            user_token_resolver=lambda _: "github-user-token",
        )

        with self.assertLogs("reposentinel.github_app", level="INFO") as captured:
            self.assertEqual(client.list_user_installations("local-user"), [501, 502])
        self.assertEqual(pages, [1, 2])
        output = "\n".join(captured.output)
        self.assertIn("token_present=True", output)
        self.assertIn("status=200", output)
        self.assertIn("installations_returned=101", output)
        self.assertIn("app_id_matches=2", output)
        self.assertNotIn("github-user-token", output)

    def test_user_installation_discovery_logs_zero_installations(self) -> None:
        settings = Settings(
            github_app_id=123,
            github_app_client_id="app-client",
            github_app_client_credential="app-secret",
            github_app_oauth_redirect_uri="http://localhost/callback",
        )
        client = GitHubAppClient(
            settings,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"installations": []})),
            user_token_resolver=lambda _: "github-app-user-token",
        )

        with self.assertLogs("reposentinel.github_app", level="INFO") as captured:
            with self.assertRaises(GitHubAppError) as context:
                client.list_user_installations("local-user")

        self.assertEqual(context.exception.code, "GITHUB_APP_NOT_INSTALLED")
        output = "\n".join(captured.output)
        self.assertIn("token_present=True", output)
        self.assertIn("status=200", output)
        self.assertIn("installations_returned=0", output)
        self.assertIn("app_id_matches=0", output)
        self.assertIn("error_code=GITHUB_APP_NOT_INSTALLED", output)
        self.assertNotIn("github-app-user-token", output)

    def test_user_installation_discovery_rejects_oauth_app_token_permissions(self) -> None:
        settings = Settings(
            github_app_id=123,
            github_app_slug="sentraforge-test",
            github_app_client_id="app-client",
            github_app_client_credential="app-secret",
            github_app_oauth_redirect_uri="http://localhost/callback",
        )

        def forbidden(_: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={"message": "Forbidden"})

        client = GitHubAppClient(settings, transport=httpx.MockTransport(forbidden), user_token_resolver=lambda _: "oauth-app-token")
        with self.assertRaises(GitHubAppError) as context:
            client.list_user_installations("local-user")
        self.assertEqual(context.exception.code, "GITHUB_PERMISSION_DENIED")
        self.assertEqual(context.exception.status_code, 403)

    def test_user_installation_discovery_rejects_no_matching_app(self) -> None:
        settings = Settings(
            github_app_id=123,
            github_app_slug="sentraforge-test",
            github_app_client_id="app-client",
            github_app_client_credential="app-secret",
            github_app_oauth_redirect_uri="http://localhost/callback",
        )

        def other_app(_: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"installations": [{"id": 9, "app_id": 999, "app_slug": "other-app"}]})

        client = GitHubAppClient(settings, transport=httpx.MockTransport(other_app), user_token_resolver=lambda _: "github-app-user-token")
        with self.assertLogs("reposentinel.github_app", level="INFO") as captured:
            with self.assertRaises(GitHubAppError) as context:
                client.list_user_installations("local-user")
        self.assertEqual(context.exception.code, "GITHUB_APP_NOT_ACCESSIBLE")
        output = "\n".join(captured.output)
        self.assertIn("token_present=True", output)
        self.assertIn("status=200", output)
        self.assertIn("installations_returned=1", output)
        self.assertIn("app_id_matches=0", output)
        self.assertIn("error_code=GITHUB_APP_NOT_ACCESSIBLE", output)
        self.assertNotIn("github-app-user-token", output)


    def test_token_cache_initialized_in_constructor(self) -> None:
        private, _ = app_key()
        settings = Settings(github_app_id=123, github_app_private_key=SecretStr(private))
        client = GitHubAppClient(settings)
        self.assertIsInstance(client._token_cache, dict)
        self.assertTrue(hasattr(client, "_token_lock"))
        with client._token_lock:
            client._token_cache[1] = ("token", 1000.0)
        self.assertEqual(client._token_cache[1][0], "token")


if __name__ == "__main__":
    unittest.main()
