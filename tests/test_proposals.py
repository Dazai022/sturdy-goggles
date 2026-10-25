import json
import tempfile
import unittest
from pathlib import Path

import httpx

from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.llm import OllamaClient, PatchProposal
from reposentinel.proposal import ProposalEligibilityError, propose_finding, validate_unified_diff


SOURCE = "value = sanitize(input_value)\nreturn value\n"
VALID_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-value = sanitize(input_value)
+value = sanitize(input_value.strip())
"""


class FakeGitHub:
    def __init__(self, source: str = SOURCE) -> None:
        self.source = source
        self.reads: list[tuple[str, str, str]] = []

    def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
        self.reads.append((full_name, path, commit_sha))
        return self.source


class FakeOllama:
    def __init__(self, proposal: PatchProposal | None = None) -> None:
        self.proposal = proposal or PatchProposal(
            proposed_diff=VALID_DIFF,
            rationale="Normalize input before use.",
            expected_behavior_change="Whitespace is removed before sanitization.",
            risks=["Behavior changes for callers that rely on whitespace."],
            validation_recommendations=["Run the existing input validation tests."],
        )
        self.calls = 0

    def propose_patch(self, **_: object) -> PatchProposal:
        self.calls += 1
        return self.proposal


def make_database(status: str = "supported") -> tuple[Database, str, tempfile.TemporaryDirectory[str]]:
    directory = tempfile.TemporaryDirectory()
    database = Database(Path(directory.name) / "state.db")
    database.initialize()
    repository_id = database.upsert_repository("acme/widget")
    scan_id = database.start_scan(repository_id, "commit123")
    file_id = database.add_scan_file(scan_id, path="app.py", sha="file123", size=len(SOURCE), status="selected")
    database.finish_scan_file(file_id, "analyzed", source_bytes=len(SOURCE.encode("utf-8")))
    finding_id = database.add_finding(
        scan_id, scanner="ollama", severity="medium", title="Input handling", evidence="sanitize(input_value)",
        remediation="Normalize input.", confidence="possible", affected_file="app.py", line_start=1, line_end=1,
        reasoning="Input is passed to a sensitive operation.", verification_steps_json='["Run tests"]',
        verification_status=status, verification_reason="citation matches", verification_method="test",
    )
    database.finish_scan(scan_id, "complete", "one finding", files_eligible=1, files_selected=1, files_scanned=1)
    return database, finding_id, directory


class ProposalTests(unittest.TestCase):
    def test_valid_supported_finding_is_proposed_and_only_reads_snapshot(self) -> None:
        database, finding_id, directory = make_database()
        self.addCleanup(directory.cleanup)
        github = FakeGitHub()
        ollama = FakeOllama()
        result = propose_finding(
            finding_id, settings=Settings(ollama_model="test-model"), database=database,
            github=github, ollama=ollama,  # type: ignore[arg-type]
        )
        self.assertEqual(result.status, "proposed")
        self.assertEqual(ollama.calls, 1)
        self.assertEqual(github.reads, [("acme/widget", "app.py", "commit123")])
        row = database.proposal(result.proposal_id)
        self.assertIsNotNone(row)
        self.assertEqual(row["validation_status"], "proposed")
        self.assertEqual(row["base_commit_sha"], "commit123")
        self.assertNotIn("write", " ".join(method for method in dir(github) if method.startswith("write")))

    def test_unverified_and_rejected_findings_are_refused(self) -> None:
        for status in ("unverified", "rejected"):
            database, finding_id, directory = make_database(status)
            self.addCleanup(directory.cleanup)
            ollama = FakeOllama()
            with self.assertRaises(ProposalEligibilityError):
                propose_finding(
                    finding_id, settings=Settings(), database=database,
                    github=FakeGitHub(), ollama=ollama,  # type: ignore[arg-type]
                )
            self.assertEqual(ollama.calls, 0)
            self.assertEqual(database.proposals(), [])

    def test_malformed_model_response_is_persisted_as_invalid(self) -> None:
        database, finding_id, directory = make_database()
        self.addCleanup(directory.cleanup)
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/chat":
                return httpx.Response(200, json={"message": {"content": "{}"}})
            return httpx.Response(200, json={"models": []})

        result = propose_finding(
            finding_id, settings=settings, database=database, github=FakeGitHub(),
            ollama=OllamaClient(settings, transport=httpx.MockTransport(handler)),
        )
        self.assertEqual(result.status, "invalid")
        self.assertIn("invalid patch proposal", database.proposal(result.proposal_id)["validation_errors"])

    def test_diff_rejects_absolute_traversal_and_unexpected_paths(self) -> None:
        for diff in (
            VALID_DIFF.replace("app.py", "C:/secret.py"),
            VALID_DIFF.replace("app.py", "../secret.py"),
            VALID_DIFF.replace("app.py", "other.py"),
        ):
            result = validate_unified_diff(diff, target_file="app.py", source=SOURCE, max_bytes=100_000)
            self.assertFalse(result.valid)
            self.assertTrue(result.errors)

    def test_base_commit_mismatch_is_refused_and_diff_persistence_is_retrievable(self) -> None:
        database, finding_id, directory = make_database()
        self.addCleanup(directory.cleanup)
        with self.assertRaises(ProposalEligibilityError):
            propose_finding(
                finding_id, settings=Settings(), database=database, github=FakeGitHub(), ollama=FakeOllama(),  # type: ignore[arg-type]
                expected_base_commit="different",
            )
        result = propose_finding(
            finding_id, settings=Settings(), database=database, github=FakeGitHub(), ollama=FakeOllama(),  # type: ignore[arg-type]
        )
        stored = database.proposal(result.proposal_id)
        self.assertEqual(stored["proposed_diff"], VALID_DIFF)
        self.assertEqual(json.loads(stored["risks_json"])[0], "Behavior changes for callers that rely on whitespace.")


if __name__ == "__main__":
    unittest.main()
