import asyncio
import base64
import tempfile
import unittest
from pathlib import Path

import httpx

from reposentinel.auth_api import create_app
from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.github_oauth import GitHubIdentity, GitHubOAuthClient, GitHubOAuthError, GitHubTokenStore, TokenCipher


class FakeOAuthProvider:
    def authorization_url(self, state: str) -> str:
        return f"https://github.test/authorize?state={state}"

    def exchange_code(self, code: str) -> str:
        if code != "valid-code":
            raise RuntimeError("exchange failed")
        return "github-oauth-token"

    def authenticated_identity(self, token: str) -> GitHubIdentity:
        return GitHubIdentity(9001, "octocat")


class FailingOAuthProvider(FakeOAuthProvider):
    def exchange_code(self, code: str) -> str:
        raise GitHubOAuthError("authorization code exchange failed", code="GITHUB_AUTH_CODE_EXCHANGE_FAILED")


class UserLookupFailingOAuthProvider(FakeOAuthProvider):
    def authenticated_identity(self, token: str) -> GitHubIdentity:
        raise GitHubOAuthError("GitHub user lookup failed", code="GITHUB_USER_LOOKUP_FAILED")


class GitHubOAuthTests(unittest.TestCase):
    def request(self, app: object, method: str, path: str, *, headers: dict[str, str] | None = None,
               json_body: dict[str, str] | None = None) -> httpx.Response:
        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.request(method, path, headers=headers, json=json_body)
        return asyncio.run(send())

    def test_oauth_callback_needs_no_bearer_and_encrypts_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            settings = Settings(
                database_path=database.path,
                github_app_state_key="state-key",
                github_token_encryption_key=base64.urlsafe_b64encode(b"e" * 32).decode(),
            )
            app = create_app(settings=settings, database=database, github_oauth=FakeOAuthProvider())
            registration = self.request(app, "POST", "/api/v1/auth/register")
            self.assertEqual(registration.status_code, 422)
            async def register() -> httpx.Response:
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                    return await client.post("/api/v1/auth/register", json={"email": "oauth@example.com", "password": "correct-horse-battery-staple"})
            registration = asyncio.run(register())
            token = registration.json()["access_token"]
            start = self.request(app, "GET", "/api/v1/github/oauth/start", headers={"Authorization": f"Bearer {token}"})
            state = start.json()["authorize_url"].split("state=", 1)[1]
            callback = self.request(app, "GET", f"/api/v1/github/oauth/callback?state={state}&code=valid-code", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(callback.status_code, 200)
            self.assertEqual(self.request(app, "GET", f"/api/v1/github/oauth/callback?state={state}&code=valid-code", headers={"Authorization": f"Bearer {token}"}).status_code, 400)
            row = database.connection()
            with row as connection:
                stored = connection.execute("SELECT encrypted_token FROM github_identities").fetchone()[0]
            self.assertNotIn(b"github-oauth-token", bytes(stored))
            self.assertEqual(GitHubTokenStore(database, TokenCipher(settings.github_token_encryption_key.get_secret_value())).get_token(registration.json()["user_id"]), "github-oauth-token")

    def test_oauth_callback_logs_sanitized_exchange_failure_stage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            settings = Settings(
                database_path=database.path,
                github_app_state_key="state-key",
                github_token_encryption_key=base64.urlsafe_b64encode(b"e" * 32).decode(),
            )
            app = create_app(settings=settings, database=database, github_oauth=FailingOAuthProvider())
            registration = self.request(
                app,
                "POST",
                "/api/v1/auth/register",
                json_body={"email": "failure@example.com", "password": "correct-horse-battery-staple"},
            )
            access_token = registration.json()["access_token"]
            start = self.request(app, "GET", "/api/v1/github/oauth/start", headers={"Authorization": f"Bearer {access_token}"})
            state = start.json()["authorize_url"].split("state=", 1)[1]

            with self.assertLogs("reposentinel.auth_api", level="WARNING") as captured:
                callback = self.request(app, "GET", f"/api/v1/github/oauth/callback?state={state}&code=one-time-code", headers={"Authorization": f"Bearer {access_token}"})

            self.assertEqual(callback.status_code, 502)
            self.assertEqual(callback.json()["detail"]["code"], "GITHUB_AUTH_CODE_EXCHANGE_FAILED")
            self.assertEqual(callback.json()["detail"]["message"], "GitHub OAuth could not be completed")
            output = "\n".join(captured.output)
            self.assertIn("stage=code_exchange", output)
            self.assertIn("code=GITHUB_AUTH_CODE_EXCHANGE_FAILED", output)
            self.assertNotIn("one-time-code", output)
            self.assertNotIn("state=", output)

    def test_oauth_callback_requires_authenticated_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            settings = Settings(
                database_path=database.path,
                github_app_state_key="state-key",
                github_token_encryption_key=base64.urlsafe_b64encode(b"e" * 32).decode(),
            )
            app = create_app(settings=settings, database=database, github_oauth=FakeOAuthProvider())
            async def register() -> httpx.Response:
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                    return await client.post("/api/v1/auth/register", json={"email": "session@example.com", "password": "correct-horse-battery-staple"})
            registration = asyncio.run(register())
            token = registration.json()["access_token"]
            start = self.request(app, "GET", "/api/v1/github/oauth/start", headers={"Authorization": f"Bearer {token}"})
            state = start.json()["authorize_url"].split("state=", 1)[1]
            callback = self.request(app, "GET", f"/api/v1/github/oauth/callback?state={state}&code=valid-code")
            self.assertEqual(callback.status_code, 401)

    def test_oauth_callback_rejects_mismatched_state_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            settings = Settings(
                database_path=database.path,
                github_app_state_key="state-key",
                github_token_encryption_key=base64.urlsafe_b64encode(b"e" * 32).decode(),
            )
            app = create_app(settings=settings, database=database, github_oauth=FakeOAuthProvider())
            async def register(email: str) -> str:
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                    response = await client.post("/api/v1/auth/register", json={"email": email, "password": "correct-horse-battery-staple"})
                    return response.json()["access_token"]
            token_a = asyncio.run(register("owner-a@example.com"))
            token_b = asyncio.run(register("owner-b@example.com"))
            start = self.request(app, "GET", "/api/v1/github/oauth/start", headers={"Authorization": f"Bearer {token_a}"})
            state = start.json()["authorize_url"].split("state=", 1)[1]
            callback = self.request(app, "GET", f"/api/v1/github/oauth/callback?state={state}&code=valid-code", headers={"Authorization": f"Bearer {token_b}"})
            self.assertEqual(callback.status_code, 403)

    def test_oauth_callback_malformed_state_returns_400(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            settings = Settings(
                database_path=database.path,
                github_app_state_key="state-key",
                github_token_encryption_key=base64.urlsafe_b64encode(b"e" * 32).decode(),
            )
            app = create_app(settings=settings, database=database, github_oauth=FakeOAuthProvider())
            async def register() -> httpx.Response:
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                    return await client.post("/api/v1/auth/register", json={"email": "malformed@example.com", "password": "correct-horse-battery-staple"})
            registration = asyncio.run(register())
            token = registration.json()["access_token"]
            for bad_state in ["not-a-state", "eyJmb28iOiJiYXIifQ==.bad", "[]", "null"]:
                callback = self.request(app, "GET", f"/api/v1/github/oauth/callback?state={bad_state}&code=valid-code", headers={"Authorization": f"Bearer {token}"})
                self.assertIn(callback.status_code, (400, 403))

    def test_verify_oauth_state_rejects_non_dict_payloads(self) -> None:
        import base64, json
        from reposentinel.github_oauth import verify_oauth_state
        for payload in ([1, 2, 3], "string", 42, None):
            encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            state = f"{encoded}.signature"
            self.assertFalse(verify_oauth_state(state, "state-key"))

    def test_identity_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            database.create_user("one@example.com", "hash")
            database.create_user("two@example.com", "hash")
            store = GitHubTokenStore(database, TokenCipher(base64.urlsafe_b64encode(b"e" * 32).decode()))
            store.ensure_schema()
            users = [database.user_by_email("one@example.com"), database.user_by_email("two@example.com")]
            store.save(str(users[0]["id"]), GitHubIdentity(7, "same"), "token-one")
            with self.assertRaises(Exception):
                store.save(str(users[1]["id"]), GitHubIdentity(7, "same"), "token-two")

    def test_github_http_exchange_and_user_lookup_are_mocked(self) -> None:
        settings = Settings(github_oauth_client_id="client", github_oauth_client_credential="credential", github_oauth_redirect_uri="http://localhost/callback")
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("access_token"):
                return httpx.Response(200, json={"access_token": "token"})
            return httpx.Response(200, json={"id": 123, "login": "octocat"})
        client = GitHubOAuthClient(settings, transport=httpx.MockTransport(handler))
        self.assertEqual(client.exchange_code("code"), "token")
        self.assertEqual(client.authenticated_identity("token"), GitHubIdentity(123, "octocat"))

    def test_github_app_user_authorization_uses_app_credentials(self) -> None:
        observed: list[dict[str, str]] = []
        settings = Settings(
            github_app_client_id="app-client",
            github_app_client_credential="app-secret",
            github_app_oauth_redirect_uri="http://localhost/app-callback",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            observed.append(dict(request.url.params) if request.method == "GET" else dict(httpx.QueryParams(request.content.decode())))
            return httpx.Response(200, json={"access_token": "app-user-token"})

        client = GitHubOAuthClient(settings, transport=httpx.MockTransport(handler))
        authorization = client.authorization_url("state-value")
        self.assertIn("client_id=app-client", authorization)
        self.assertIn("redirect_uri=http%3A%2F%2Flocalhost%2Fapp-callback", authorization)
        self.assertNotIn("scope=read%3Auser", authorization)
        self.assertEqual(client.exchange_code("code"), "app-user-token")
        self.assertEqual(observed[0]["client_id"], "app-client")
