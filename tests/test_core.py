import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from typer.testing import CliRunner

from reposentinel.allowlist import RepositoryAllowlist
from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.cli import app
from reposentinel.llm import OllamaClient, read_source_file
from reposentinel.report import build_report
from reposentinel.verification import FindingVerificationStatus, verify_finding_evidence
from reposentinel.llm import SecurityFinding


class DatabaseTests(unittest.TestCase):
    def test_initialization_is_idempotent_and_persists_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            database.initialize()
            repository_id = database.upsert_repository("Acme/Widget", default_branch="main")
            scan_id = database.start_scan(repository_id)
            database.finish_scan(scan_id, "complete", "No findings")
            rows = database.history()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["full_name"], "acme/widget")
            self.assertEqual(rows[0]["status"], "complete")

    def test_transaction_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            with self.assertRaises(RuntimeError):
                with database.connection() as connection:
                    connection.execute("INSERT INTO repositories(id, full_name, created_at, updated_at) VALUES ('x', 'a/b', 'x', 'x')")
                    raise RuntimeError("interrupt")
            self.assertEqual(database.list_repositories(), [])

    def test_finding_verification_and_report_persistence(self) -> None:
        finding = SecurityFinding(
            title="Test finding", severity="medium", confidence=0.7, affected_file="app.py",
            line_start=2, line_end=2, evidence="dangerous()", reasoning="Call may be unsafe.",
            recommended_remediation="Review the call.", verification_steps=["Add a test."],
            attack_path="An attacker reaches the call through the request value.",
            affected_security_property="confidentiality",
            attacker_prerequisites="A request containing a sensitive value.",
            concrete_impact="The sensitive value could be written to logs.",
        )
        supported = verify_finding_evidence(finding, source="safe()\ndangerous()\n", relative_path="app.py")
        self.assertEqual(supported.status, FindingVerificationStatus.SUPPORTED)
        missing = verify_finding_evidence(finding.model_copy(update={"evidence": "not-present"}), source="safe()\ndangerous()\n", relative_path="app.py")
        self.assertEqual(missing.status, FindingVerificationStatus.REJECTED)
        out_of_range = verify_finding_evidence(finding.model_copy(update={"line_start": 3, "line_end": 3}), source="safe()\ndangerous()\n", relative_path="app.py")
        self.assertEqual(out_of_range.status, FindingVerificationStatus.REJECTED)
        invalid_range = verify_finding_evidence(finding.model_copy(update={"line_start": 0, "line_end": 1}), source="safe()\ndangerous()\n", relative_path="app.py")
        self.assertEqual(invalid_range.status, FindingVerificationStatus.REJECTED)
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            repository_id = database.upsert_repository("acme/widget")
            scan_id = database.start_scan(repository_id, "sha")
            database.add_finding(
                scan_id, scanner="ollama", severity="medium", title=finding.title, evidence=finding.evidence,
                remediation=finding.recommended_remediation, confidence="possible", affected_file="app.py",
                line_start=2, line_end=2, reasoning=finding.reasoning,
                verification_steps_json=json.dumps(finding.verification_steps),
                verification_status="rejected", verification_reason="bad citation", verification_method="test",
            )
            database.finish_scan(scan_id, "incomplete", "assessment failed", error="one file failed", files_eligible=2, files_selected=2, files_scanned=1, files_failed=1)
            report = build_report(database, scan_id)
            self.assertEqual(report["scan"]["status"], "incomplete")
            self.assertEqual(report["findings"][0]["verification_status"], "rejected")
            self.assertEqual(report["findings"][0]["file"], "app.py")
            self.assertIn("not proof", " ".join(report["limitations"]))

    def test_report_revalidation_records_reason_without_upgrading_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            repository_id = database.upsert_repository("acme/widget")
            scan_id = database.start_scan(repository_id, "sha")
            finding_id = database.add_finding(
                scan_id, scanner="ollama", severity="medium", title="Historical", evidence="dangerous()",
                remediation="Review", confidence="possible", affected_file="app.py", line_start=1, line_end=1,
                reasoning="Historical finding", verification_steps_json="[]", verification_status="unverified",
            )
            database.finish_scan(scan_id, "complete", "Historical result")

            class ReadOnlyGitHub:
                def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
                    return "dangerous()\n"

            report = build_report(database, scan_id, github=ReadOnlyGitHub())  # type: ignore[arg-type]
            self.assertEqual(report["findings"][0]["verification_status"], "unverified")
            self.assertIn("match the pinned source", report["findings"][0]["verification_reason"])
            self.assertEqual(database.finding(finding_id)["verification_status"], "unverified")

    def test_export_command_writes_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "state.db"
            database = Database(db_path)
            database.initialize()
            repository_id = database.upsert_repository("acme/widget")
            scan_id = database.start_scan(repository_id, "sha")
            database.finish_scan(scan_id, "complete", "No findings", files_eligible=1, files_selected=1, files_scanned=1)
            output = Path(directory) / "report.json"
            with patch("reposentinel.cli.get_settings", return_value=Settings(database_path=db_path)):
                result = CliRunner().invoke(app, ["export", str(output)])
            self.assertEqual(result.exit_code, 0, result.stdout)
            exported = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(exported["repository"], "acme/widget")
            self.assertEqual(exported["scan"]["status"], "complete")


class ConfigurationTests(unittest.TestCase):
    def test_repository_list_is_parsed_and_token_is_not_printable(self) -> None:
        with patch.dict(os.environ, {"REPOSENTINEL_ALLOWED_REPOSITORIES": "Acme/One, acme/two", "REPOSENTINEL_GITHUB_TOKEN": "secret"}, clear=False):
            settings = Settings()
            self.assertEqual(settings.allowed_repositories, ["acme/one", "acme/two"])
            self.assertEqual(settings.github_token.get_secret_value(), "secret")
            self.assertNotIn("secret", str(settings))


class AllowlistTests(unittest.TestCase):
    def test_matching_is_case_insensitive_and_unknown_is_rejected(self) -> None:
        allowlist = RepositoryAllowlist.from_values(["Acme/Widget"])
        self.assertTrue(allowlist.contains("acme/widget"))
        with self.assertRaises(PermissionError):
            allowlist.require("other/repo")


class OllamaTests(unittest.TestCase):
    def test_prompt_contains_line_numbered_source_and_no_finding_instruction(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)
        requests: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(json.loads(request.content))
            valid = {"status": "clean", "summary": "No evidence", "reasoning": "Insufficient evidence", "findings": [], "limitations": ["No issue established"]}
            return httpx.Response(200, json={"message": {"content": json.dumps(valid)}})

        OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="first()\nsecond()\n", relative_path="app.py")
        prompt = requests[0]["messages"][1]["content"]
        self.assertIn("     1 | first()", prompt)
        self.assertIn("     2 | second()", prompt)
        self.assertIn("return status=clean with findings=[]", prompt)
        self.assertIn("SOURCE START (line number, delimiter, exact source text)", prompt)

    def test_fabricated_evidence_outside_cited_lines_is_rejected(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)

        def handler(request: httpx.Request) -> httpx.Response:
            finding = {
                "title": "Fabricated", "severity": "high", "confidence": 0.8,
                "affected_file": "app.py", "line_start": 1, "line_end": 1,
                "evidence": "second()", "reasoning": "Not in cited line.",
                "recommended_remediation": "Review", "verification_steps": ["Test"],
                "attack_path": "A caller reaches the returned value.",
                "affected_security_property": "confidentiality",
                "attacker_prerequisites": "A caller can invoke the function.",
                "concrete_impact": "The returned value could be exposed.",
            }
            assessment = {"status": "possible", "summary": "Issue", "reasoning": "Issue", "findings": [finding], "limitations": []}
            return httpx.Response(200, json={"message": {"content": json.dumps(assessment)}})

        with self.assertRaises(ValueError) as error:
            OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="first()\nsecond()\n", relative_path="app.py")
        self.assertIn("cited lines", str(error.exception))

    def test_raw_response_return_without_unsafe_use_can_be_clean(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)
        source = "response = client.complete(prompt)\nreturn response.choices[0].message.content\n"

        def handler(request: httpx.Request) -> httpx.Response:
            clean = {
                "status": "clean", "summary": "No concrete security issue established",
                "reasoning": "Returning a response is not itself an unsafe sink.", "findings": [],
                "limitations": ["No evidence of sensitive data exposure or unauthorized downstream use."],
            }
            return httpx.Response(200, json={"message": {"content": json.dumps(clean)}})

        assessment = OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source=source, relative_path="llm_service.py")
        self.assertEqual(assessment.status.value, "clean")
        self.assertEqual(assessment.findings, [])

    def test_unsafe_downstream_data_flow_remains_detectable(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)
        source = "response = client.complete(prompt)\nlogger.info(response.choices[0].message.content)\n"

        def handler(request: httpx.Request) -> httpx.Response:
            finding = {
                "title": "Raw model response logged", "severity": "high", "confidence": 0.9,
                "affected_file": "llm_service.py", "line_start": 2, "line_end": 2,
                "evidence": "logger.info(response.choices[0].message.content)",
                "reasoning": "The model response is sent to a log sink without sanitization.",
                "recommended_remediation": "Redact sensitive content before logging.",
                "verification_steps": ["Assert sensitive response content is not logged."],
                "attack_path": "An attacker causes sensitive model output and triggers this log call.",
                "affected_security_property": "confidentiality",
                "attacker_prerequisites": "Ability to influence the prompt and access application logs.",
                "concrete_impact": "Sensitive model output can persist in logs and be read by log consumers.",
            }
            assessment = {"status": "possible", "summary": "Unsafe logging sink", "reasoning": "A concrete log sink is present.", "findings": [finding], "limitations": []}
            return httpx.Response(200, json={"message": {"content": json.dumps(assessment)}})

        assessment = OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source=source, relative_path="llm_service.py")
        self.assertEqual(len(assessment.findings), 1)
        self.assertEqual(assessment.findings[0].line_start, 2)
        self.assertEqual(assessment.findings[0].concrete_impact, "Sensitive model output can persist in logs and be read by log consumers.")

    def test_mocked_ollama_assessment_is_schema_validated_and_evidence_bound(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)
        source = "password = request.args.get('password')\nprint(password)\n"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/chat":
                content = {
                    "status": "confirmed",
                    "summary": "Potential credential exposure",
                    "reasoning": "A value named password is read from a request and printed.",
                    "findings": [{
                        "title": "Sensitive value printed",
                        "severity": "medium",
                        "confidence": 0.8,
                        "affected_file": "app.py",
                        "line_start": 1,
                        "line_end": 2,
                        "evidence": "password = request.args.get('password')",
                        "reasoning": "The password value is printed on the next line.",
                        "recommended_remediation": "Avoid logging sensitive request values.",
                        "verification_steps": ["Add a regression test that asserts sensitive values are not logged."],
                "attack_path": "A request supplies a sensitive value that reaches the print call.",
                "affected_security_property": "confidentiality",
                "attacker_prerequisites": "Ability to submit a request containing a sensitive value.",
                "concrete_impact": "The sensitive value is exposed through application logs.",
                    }],
                    "limitations": [],
                }
                return httpx.Response(200, json={"message": {"content": __import__("json").dumps(content)}})
            return httpx.Response(200, json={"models": []})

        client = OllamaClient(settings, transport=httpx.MockTransport(handler))
        self.assertTrue(client.check_connectivity())
        assessment = client.analyze(source=source, relative_path="app.py")
        self.assertEqual(assessment.status, "confirmed")
        self.assertEqual(assessment.findings[0].line_start, 1)

    def test_source_path_cannot_escape_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            root.mkdir()
            outside = Path(directory) / "outside.py"
            outside.write_text("print('x')", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_source_file(outside, root=root, max_bytes=1000)


if __name__ == "__main__":
    unittest.main()
