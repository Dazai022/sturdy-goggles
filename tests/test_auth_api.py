import asyncio
import sqlite3
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from reposentinel.auth_api import create_app
from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.github_app import GitHubAppClient, InstallationInfo, InstallationRepository


class FakeInstallationProvider:
    def is_user_authorized(self, installation_id: int, user_id: str) -> bool:
        return True

    def get_installation(self, installation_id: int) -> InstallationInfo:
        return InstallationInfo(installation_id, "acme", "Organization", {"contents": "read"})

    def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]:
        return [
            InstallationRepository(101, "acme/one", "main", "one", False),
            InstallationRepository(102, "acme/two", "trunk", "two", True),
        ]


class AuthApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.directory.name) / "state.db")
        self.database.initialize()
        self.settings = Settings(
            database_path=Path(self.directory.name) / "state.db",
            github_app_slug="sentraforge-test",
            github_app_state_key="state-key-for-tests",
        )
        self.app = create_app(settings=self.settings, database=self.database, github_app=FakeInstallationProvider())

    def tearDown(self) -> None:
        self.directory.cleanup()

    def request(self, method: str, path: str, *, json_body: object | None = None,
                headers: dict[str, str] | None = None, params: dict[str, object] | None = None) -> httpx.Response:
        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.request(method, path, json=json_body, headers=headers, params=params)
        return asyncio.run(send())

    def register(self, email: str) -> tuple[str, str]:
        response = self.request("POST", "/api/v1/auth/register", json_body={
            "email": email, "password": "correct-horse-battery-staple",
        })
        self.assertEqual(response.status_code, 201)
        body = response.json()
        return str(body["access_token"]), str(body["user_id"])

    def test_registration_login_logout_and_password_is_not_stored_plaintext(self) -> None:
        token, user_id = self.register("Alice@example.test")
        row = self.database.user_by_id(user_id)
        self.assertIsNotNone(row)
        self.assertNotEqual(row["password_hash"], "correct-horse-battery-staple")
        login = self.request("POST", "/api/v1/auth/login", json_body={
            "email": "alice@example.test", "password": "correct-horse-battery-staple",
        })
        self.assertEqual(login.status_code, 200)
        self.assertEqual(self.request("POST", "/api/v1/auth/login", json_body={
            "email": "alice@example.test", "password": "wrong-password-long",
        }).status_code, 401)
        self.assertEqual(self.request("POST", "/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"}).status_code, 204)
        self.assertEqual(self.request("GET", "/api/v1/repositories", headers={"Authorization": f"Bearer {token}"}).status_code, 401)

    def test_github_identity_status_is_credential_free_and_user_scoped(self) -> None:
        token, _ = self.register("identity@example.test")
        response = self.request("GET", "/api/v1/github/identity", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"connected": False, "github_user_id": None, "github_login": None})

    def test_installation_callback_discovers_and_persists_per_user_repositories(self) -> None:
        token, _ = self.register("alice@example.test")
        start = self.request("GET", "/api/v1/github/installations/start", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(start.status_code, 200)
        state = parse_qs(urlsplit(start.json()["install_url"]).query)["state"][0]
        callback = self.request("POST", "/api/v1/github/installations/callback", params={
            "state": state, "installation_id": 77,
        }, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(callback.status_code, 200)
        self.assertEqual(callback.json()["repositories_discovered"], 2)
        repositories = self.request("GET", "/api/v1/repositories", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual([item["github_repo_id"] for item in repositories.json()], [101, 102])

    def test_selection_is_isolated_between_users(self) -> None:
        alice_token, _ = self.register("alice@example.test")
        bob_token, _ = self.register("bob@example.test")
        start = self.request("GET", "/api/v1/github/installations/start", headers={"Authorization": f"Bearer {alice_token}"})
        state = parse_qs(urlsplit(start.json()["install_url"]).query)["state"][0]
        self.request("POST", "/api/v1/github/installations/callback", params={"state": state, "installation_id": 77}, headers={"Authorization": f"Bearer {alice_token}"})
        self.assertEqual(self.request("PUT", "/api/v1/repositories/101/selection", json_body={"selected": True}, headers={"Authorization": f"Bearer {bob_token}"}).status_code, 404)
        self.assertEqual(self.request("PUT", "/api/v1/repositories/101/selection", json_body={"selected": True}, headers={"Authorization": f"Bearer {alice_token}"}).json()["selected"], True)
        self.assertEqual(self.request("GET", "/api/v1/repositories", headers={"Authorization": f"Bearer {bob_token}"}).json(), [])

    def test_invalid_installation_state_and_provider_fail_safely(self) -> None:
        token, _ = self.register("alice@example.test")
        response = self.request("POST", "/api/v1/github/installations/callback", params={"state": "tampered", "installation_id": 77}, headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 400)

    def test_github_app_repository_pagination_is_mocked(self) -> None:
        calls: list[int] = []
        settings = Settings(github_api_url="https://api.github.test")

        def handler(request: httpx.Request) -> httpx.Response:
            page = int(request.url.params["page"])
            calls.append(page)
            count = 100 if page == 1 else 1
            items = [{"id": page * 1000 + i, "full_name": f"acme/repo-{page}-{i}", "private": False} for i in range(count)]
            headers = {"link": '<https://api.github.test/next>; rel="next"'} if page == 1 else {}
            return httpx.Response(200, json={"total_count": 101, "repositories": items}, headers=headers)

        client = GitHubAppClient(settings, installation_token="test-installation-token", transport=httpx.MockTransport(handler))
        repositories = client.list_installation_repositories(42)
        self.assertEqual(calls, [1, 2])
        self.assertEqual(len(repositories), 101)
        self.assertEqual(repositories[0].full_name, "acme/repo-1-0")

    def test_schema_migration_adds_multi_user_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
                connection.execute("INSERT INTO schema_version(version) VALUES (8)")
                connection.commit()
            finally:
                connection.close()
            database = Database(path)
            database.initialize()
            connection = sqlite3.connect(path)
            try:
                version = connection.execute("SELECT version FROM schema_version").fetchone()[0]
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            finally:
                connection.close()
            self.assertEqual(version, 9)
            self.assertTrue({"users", "sessions", "github_installations", "user_installations", "user_repositories"} <= tables)


if __name__ == "__main__":
    unittest.main()
