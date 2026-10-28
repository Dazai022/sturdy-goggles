import asyncio
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from reposentinel.auth_api import create_app
from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.github_app import InstallationInfo, InstallationRepository


class MutableProvider:
    def __init__(self) -> None:
        self.discoverable = False
        self.repositories = [
            InstallationRepository(1, "acme/one", "main", "one", False),
            InstallationRepository(2, "acme/two", "main", "two", True),
        ]

    def is_user_authorized(self, installation_id: int, user_id: str) -> bool:
        return user_id == self.authorized_user

    def list_user_installations(self, user_id: str) -> list[int]:
        return [77] if self.discoverable and user_id == self.authorized_user else []

    def get_installation(self, installation_id: int) -> InstallationInfo:
        return InstallationInfo(installation_id, "acme", "Organization", {"contents": "read"})

    def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]:
        return list(self.repositories)

    authorized_user = ""


class RepositorySyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.directory.name) / "state.db")
        self.database.initialize()
        self.provider = MutableProvider()
        self.settings = Settings(
            database_path=Path(self.directory.name) / "state.db",
            github_app_slug="sentraforge-test",
            github_app_state_key="sync-state-key",
            github_app_redirect_uri="http://127.0.0.1:8000/api/v1/github/installations/callback",
        )
        self.app = create_app(settings=self.settings, database=self.database, github_app=self.provider)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def request(self, method: str, path: str, *, token: str, params: dict[str, object] | None = None,
                body: object | None = None) -> httpx.Response:
        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.request(method, path, params=params, json=body,
                                            headers={"Authorization": f"Bearer {token}"})
        return asyncio.run(send())

    def register(self, email: str) -> tuple[str, str]:
        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.post("/api/v1/auth/register", json={"email": email, "password": "correct-horse-battery-staple"})
        response = asyncio.run(send())
        self.assertEqual(response.status_code, 201)
        body = response.json()
        return str(body["access_token"]), str(body["user_id"])

    def associate(self, token: str, user_id: str) -> None:
        self.provider.authorized_user = user_id
        started = self.request("GET", "/api/v1/github/installations/start", token=token)
        state = parse_qs(urlsplit(started.json()["install_url"]).query)["state"][0]
        callback = self.request("POST", "/api/v1/github/installations/callback", token=token,
                                params={"state": state, "installation_id": 77})
        self.assertEqual(callback.status_code, 200)

    def test_sync_is_user_scoped_paginated_data_and_preserves_selection(self) -> None:
        token, user_id = self.register("sync@example.test")
        self.associate(token, user_id)
        selected = self.request("PUT", "/api/v1/repositories/1/selection", token=token, body={"selected": True})
        self.assertEqual(selected.status_code, 200)

        self.provider.repositories = [InstallationRepository(1, "acme/renamed", "main", "renamed", False)]
        response = self.request("POST", "/api/v1/repositories/sync", token=token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["repositories_synchronized"], 1)
        repositories = self.request("GET", "/api/v1/repositories", token=token).json()
        self.assertEqual(len(repositories), 1)
        self.assertEqual(repositories[0]["github_repo_id"], 1)
        self.assertTrue(repositories[0]["selected"])
        self.assertEqual(repositories[0]["full_name"], "acme/renamed")

    def test_installation_start_carries_callback_redirect(self) -> None:
        token, _ = self.register("redirect@example.test")
        response = self.request("GET", "/api/v1/github/installations/start", token=token)
        query = parse_qs(urlsplit(response.json()["install_url"]).query)
        self.assertEqual(query["redirect_uri"], [self.settings.github_app_redirect_uri])

    def test_sync_discovers_existing_installation_without_reinstall(self) -> None:
        token, user_id = self.register("existing-installation@example.test")
        self.provider.authorized_user = user_id
        self.provider.discoverable = True

        response = self.request("POST", "/api/v1/repositories/sync", token=token)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "installations_synchronized": 1,
            "repositories_synchronized": 2,
        })
        repositories = self.request("GET", "/api/v1/repositories", token=token).json()
        self.assertEqual([item["github_repo_id"] for item in repositories], [1, 2])

    def test_sync_without_association_is_explicit_error_and_provider_failure_is_not_empty_success(self) -> None:
        token, _ = self.register("unassociated@example.test")
        response = self.request("POST", "/api/v1/repositories/sync", token=token)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"]["code"], "GITHUB_APP_NOT_INSTALLED")

        token, user_id = self.register("failure@example.test")
        self.associate(token, user_id)
        self.provider.repositories = None  # type: ignore[assignment]
        response = self.request("POST", "/api/v1/repositories/sync", token=token)
        self.assertEqual(response.status_code, 502)


if __name__ == "__main__":
    unittest.main()
