import asyncio
import tempfile
import unittest
from pathlib import Path

import httpx

from reposentinel.api import create_app
from reposentinel.config import Settings
from reposentinel.db import Database


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.directory.name) / "state.db")
        self.database.initialize()
        self.database.upsert_repository("acme/widget", default_branch="main")
        self.database.set_repository_selection("acme/widget", True)
        self.settings = Settings(api_token="local-demo-token", database_path=Path(self.directory.name) / "state.db")
        self.app = create_app(settings=self.settings, database=self.database)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def request(self, method: str, path: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                return await client.request(method, path, headers=headers)

        return asyncio.run(send())

    def test_health_is_non_secret_and_read_only(self) -> None:
        response = self.request("GET", "/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "read_only": True, "api_token_configured": True})

    def test_protected_repository_endpoint_requires_bearer_token(self) -> None:
        self.assertEqual(self.request("GET", "/api/v1/repositories").status_code, 401)
        response = self.request("GET", "/api/v1/repositories", headers={"Authorization": "Bearer local-demo-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["full_name"], "acme/widget")
        self.assertTrue(response.json()[0]["is_allowed"])

    def test_scan_report_endpoint_returns_not_found_without_mutation(self) -> None:
        response = self.request(
            "GET",
            "/api/v1/scans/not-a-real-scan/report",
            headers={"Authorization": "Bearer local-demo-token"},
        )
        self.assertEqual(response.status_code, 404)
        self.assertIsNone(self.database.latest_scan("acme/widget"))

    def test_health_does_not_expose_api_token(self) -> None:
        self.assertNotIn("local-demo-token", self.request("GET", "/health").text)


if __name__ == "__main__":
    unittest.main()
