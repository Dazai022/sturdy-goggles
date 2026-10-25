import base64
import json
import tempfile
import unittest
from pathlib import Path

import httpx

from reposentinel.config import Settings
from reposentinel.db import Database, ScanAlreadyRunning
from reposentinel.github import AuthenticationError, GitHubClient, RateLimitError, GitHubRepository, GitHubTreeEntry
from reposentinel.llm import AssessmentValidationError, OllamaClient, OllamaUnavailable, SecurityAssessment
from reposentinel.report import build_report
from reposentinel.scanner import scan_repository


def repo_payload(name: str = "acme/widget") -> dict[str, object]:
    return {"full_name": name, "default_branch": "main", "description": "test", "private": True}


class GitHubClientTests(unittest.TestCase):
    def test_repository_pagination(self) -> None:
        calls: list[int] = []

        def handler(request: httpx.Request) -> httpx.Response:
            page = int(request.url.params["page"])
            calls.append(page)
            payload = [repo_payload(f"acme/repo-{page}-{index}") for index in range(100 if page == 1 else 1)]
            headers = {"link": '<https://api.github.test/user/repos?page=2>; rel="next"'} if page == 1 else {}
            return httpx.Response(200, json=payload, headers=headers)

        settings = Settings(github_token="token", github_api_url="https://api.github.test")
        repositories = GitHubClient(settings, transport=httpx.MockTransport(handler)).list_repositories()
        self.assertEqual(calls, [1, 2])
        self.assertEqual(len(repositories), 101)

    def test_authentication_and_rate_limit_errors_are_distinct(self) -> None:
        settings = Settings(github_token="never-print-this", github_api_url="https://api.github.test")

        def auth_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"message": "bad credentials"})

        with self.assertRaises(AuthenticationError) as auth_error:
            GitHubClient(settings, transport=httpx.MockTransport(auth_handler)).list_repositories()
        self.assertNotIn("never-print-this", str(auth_error.exception))

        def rate_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, headers={"x-ratelimit-remaining": "0"})

        with self.assertRaises(RateLimitError):
            GitHubClient(settings, transport=httpx.MockTransport(rate_handler)).list_repositories()


class ScanTests(unittest.TestCase):
    def test_valid_empty_finding_assessment_is_accepted(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)
        valid = {
            "status": "clean",
            "summary": "No supported issue in the supplied source.",
            "reasoning": "The file contains no security-relevant behavior.",
            "findings": [],
            "limitations": ["Assessment is limited to this source file."],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/chat")
            return httpx.Response(200, json={"message": {"content": json.dumps(valid)}})

        assessment = OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(
            source="# package marker\n", relative_path="backend/services/__init__.py"
        )
        self.assertEqual(assessment.status.value, "clean")
        self.assertEqual(assessment.findings, [])

    def test_typescript_layout_can_return_valid_clean_assessment(self) -> None:
        source = "import type { Metadata } from 'next';\n\nexport const metadata: Metadata = { title: 'App' };\n\nexport default function Layout({ children }: { children: React.ReactNode }) {\n    return <html><body>{children}</body></html>;\n}\n"
        valid = {
            "status": "clean",
            "summary": "No concrete security issue in the supplied layout component.",
            "reasoning": "The component contains static metadata and renders its children without a source-grounded security sink.",
            "findings": [],
            "limitations": ["Assessment is limited to this component."],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            self.assertIn("frontend/app/layout.tsx", payload["messages"][1]["content"])
            self.assertIn("TypeScript, JSX, and JavaScript syntax are supported", payload["messages"][1]["content"])
            return httpx.Response(200, json={"message": {"content": json.dumps(valid)}})

        assessment = OllamaClient(
            Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0),
            transport=httpx.MockTransport(handler),
        ).analyze(source=source, relative_path="frontend/app/layout.tsx")
        self.assertEqual(assessment.status.value, "clean")
        self.assertEqual(assessment.findings, [])

    def test_sanitizer_module_can_return_a_source_grounded_finding(self) -> None:
        source = "def sanitize(value):\n    return value.replace('<', '&lt;')\n"
        finding = {
            "title": "Incomplete HTML escaping", "severity": "medium", "confidence": 0.91,
            "affected_file": "backend/sanitizers/masker.py", "line_start": 2, "line_end": 2,
            "evidence": "return value.replace('<', '&lt;')",
            "reasoning": "The sanitizer replaces only one character and leaves quote characters unchanged in an HTML context.",
            "recommended_remediation": "Use a context-appropriate HTML escaping routine.",
            "verification_steps": ["Test quote and angle-bracket payloads in the rendered HTML context."],
            "attack_path": "An attacker supplies a value containing an unescaped quote that reaches an HTML sink after this function.",
            "affected_security_property": "integrity of rendered HTML",
            "attacker_prerequisites": "Ability to control the value passed to sanitize in an HTML-rendering path.",
            "concrete_impact": "The returned value can preserve a quote character that breaks the intended escaping boundary.",
        }
        response = {"status": "possible", "summary": "A source-grounded sanitizer concern", "reasoning": "The cited line shows the incomplete escaping operation.", "findings": [finding], "limitations": []}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"content": json.dumps(response)}})

        assessment = OllamaClient(
            Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0),
            transport=httpx.MockTransport(handler),
        ).analyze(source=source, relative_path="backend/sanitizers/masker.py")
        self.assertEqual(assessment.status.value, "possible")
        self.assertEqual(assessment.findings[0].line_start, 2)
        self.assertEqual(assessment.findings[0].evidence, "return value.replace('<', '&lt;')")

    def test_complex_module_may_remain_incomplete_when_context_is_insufficient(self) -> None:
        response = {
            "status": "incomplete", "summary": "The supplied module needs deployment context.",
            "reasoning": "The file alone cannot establish the security boundary.", "findings": [],
            "limitations": ["Callers and deployment context are not supplied."],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"content": json.dumps(response)}})

        assessment = OllamaClient(
            Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0),
            transport=httpx.MockTransport(handler),
        ).analyze(source="\n".join(f"line_{i} = value_{i}" for i in range(1, 40)), relative_path="backend/complex.py")
        self.assertEqual(assessment.status.value, "incomplete")
        self.assertEqual(assessment.findings, [])

    def test_incomplete_assessments_persist_sanitized_diagnostics_for_both_failure_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            database.upsert_repository("acme/widget")
            database.set_repository_selection("acme/widget", True)
            sources = {
                "backend/services/__init__.py": "# package marker\n",
                "backend/services/llm_service.py": "def generate_response(prompt):\n    return prompt\n",
            }

            class FakeGitHub:
                def get_repository(self, full_name: str) -> GitHubRepository:
                    return GitHubRepository("acme/widget", "main", "test", False)

                def get_default_branch_sha(self, repository: GitHubRepository) -> str:
                    return "pinned-sha"

                def list_source_files(self, full_name: str, commit_sha: str, extensions: list[str]) -> tuple[list[GitHubTreeEntry], bool]:
                    return [GitHubTreeEntry(path, f"sha-{index}", len(source.encode())) for index, (path, source) in enumerate(sources.items())], False

                def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
                    return sources[path]

            class IncompleteOllama:
                def check_connectivity(self) -> bool:
                    return True

                def analyze(self, *, source: str, relative_path: str) -> SecurityAssessment:
                    return SecurityAssessment(
                        status="incomplete",
                        summary="Model could not complete this bounded assessment.",
                        reasoning="Insufficient context.",
                        findings=[],
                        limitations=["Additional context would be required."],
                    )

            result = scan_repository(
                "acme/widget", settings=Settings(scan_max_files=2), database=database,
                github=FakeGitHub(), ollama=IncompleteOllama(),  # type: ignore[arg-type]
            )
            self.assertEqual(result.status, "incomplete")
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(result.files_failed, 2)
            self.assertEqual(result.files_skipped, 0)
            self.assertTrue(all(error.startswith("backend/services/") for error in result.errors))
            self.assertTrue(all("assessment-incomplete" in error for error in result.errors))
            self.assertTrue(all("structured response parsed" in error for error in result.errors))
            history = database.history()
            self.assertIn("assessment-incomplete", history[0]["error"])
            self.assertNotIn("generate_response", history[0]["error"])

    def test_complete_scan_persists_supported_synthetic_finding_and_report(self) -> None:
        source = 'password = request.args["password"]\nprint(password)\n'
        finding = {
            "title": "Plaintext password logged", "severity": "high", "confidence": 0.95,
            "affected_file": "app.py", "line_start": 2, "line_end": 2,
            "evidence": "print(password)",
            "reasoning": "The fixture logs a password value directly.",
            "recommended_remediation": "Remove sensitive values from logs.",
            "verification_steps": ["Assert the password is not written to logs."],
            "attack_path": "A request supplies a password that reaches the print call.",
            "affected_security_property": "confidentiality",
            "attacker_prerequisites": "Ability to submit a request containing a password.",
            "concrete_impact": "The password is exposed through application logs.",
        }
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            database.upsert_repository("acme/widget")
            database.set_repository_selection("acme/widget", True)

            class FakeGitHub:
                def get_repository(self, full_name: str) -> GitHubRepository:
                    return GitHubRepository("acme/widget", "main", "test", False)

                def get_default_branch_sha(self, repository: GitHubRepository) -> str:
                    return "fixedsha"

                def list_source_files(self, full_name: str, commit_sha: str, extensions: list[str]) -> tuple[list[GitHubTreeEntry], bool]:
                    return [GitHubTreeEntry("app.py", "filesha", len(source.encode("utf-8")))], False

                def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
                    return source

            class FakeOllama:
                def check_connectivity(self) -> bool:
                    return True

                def analyze(self, *, source: str, relative_path: str) -> SecurityAssessment:
                    return SecurityAssessment(status="confirmed", summary="Sensitive logging", reasoning="The fixture contains a sensitive log call.", findings=[finding], limitations=[])

            result = scan_repository(
                "acme/widget", settings=Settings(scan_max_files=1), database=database,
                github=FakeGitHub(), ollama=FakeOllama(),  # type: ignore[arg-type]
            )
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.commit_sha, "fixedsha")
            self.assertEqual(result.files_scanned, 1)
            scan = database.latest_scan("acme/widget")
            self.assertEqual(scan["commit_sha"], "fixedsha")
            stored = database.findings(scan["id"])
            self.assertEqual(len(stored), 1)
            self.assertEqual(stored[0]["line_start"], 2)
            self.assertEqual(stored[0]["line_end"], 2)
            self.assertEqual(stored[0]["verification_status"], "supported")
            report = build_report(database, scan["id"])
            self.assertEqual(report["commit_sha"], "fixedsha")
            self.assertEqual(report["findings"][0]["verification_status"], "supported")

    def test_clean_synthetic_scan_completes_with_zero_findings(self) -> None:
        source = "def add(left, right):\n    return left + right\n"
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            database.upsert_repository("acme/clean")
            database.set_repository_selection("acme/clean", True)

            class FakeGitHub:
                def get_repository(self, full_name: str) -> GitHubRepository:
                    return GitHubRepository("acme/clean", "main", "test", False)

                def get_default_branch_sha(self, repository: GitHubRepository) -> str:
                    return "cleansha"

                def list_source_files(self, full_name: str, commit_sha: str, extensions: list[str]) -> tuple[list[GitHubTreeEntry], bool]:
                    return [GitHubTreeEntry("math.py", "filesha", len(source.encode("utf-8")))], False

                def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
                    return source

            class FakeOllama:
                def check_connectivity(self) -> bool:
                    return True

                def analyze(self, *, source: str, relative_path: str) -> SecurityAssessment:
                    return SecurityAssessment(status="clean", summary="No supported issue", reasoning="The supplied fixture has no security evidence.", findings=[], limitations=[])

            result = scan_repository(
                "acme/clean", settings=Settings(scan_max_files=1), database=database,
                github=FakeGitHub(), ollama=FakeOllama(),  # type: ignore[arg-type]
            )
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.findings, 0)
            scan = database.latest_scan("acme/clean")
            self.assertEqual(database.findings(scan["id"]), [])

    def test_allowlist_and_incomplete_scan_are_enforced_and_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            repository_id = database.upsert_repository("acme/widget")
            with self.assertRaises(PermissionError):
                scan_repository("acme/widget", settings=Settings(scan_max_files=2), database=database, github=object(), ollama=object())  # type: ignore[arg-type]

            database.set_repository_selection("acme/widget", True)

            class FakeGitHub:
                def get_repository(self, full_name: str) -> GitHubRepository:
                    return GitHubRepository("acme/widget", "main", "test", True)

                def get_default_branch_sha(self, repository: GitHubRepository) -> str:
                    return "abc123"

                def list_source_files(self, full_name: str, commit_sha: str, extensions: list[str]) -> tuple[list[GitHubTreeEntry], bool]:
                    return [GitHubTreeEntry("app.py", "one", 10), GitHubTreeEntry("large.py", "two", 999), GitHubTreeEntry("third.py", "three", 10)], False

                def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
                    return "print('hello')\n"

            class FakeOllama:
                def check_connectivity(self) -> bool:
                    return True

                def analyze(self, *, source: str, relative_path: str) -> SecurityAssessment:
                    return SecurityAssessment(status="clean", summary="No evidence", reasoning="No supported evidence", findings=[], limitations=[])

            result = scan_repository(
                "acme/widget",
                settings=Settings(scan_max_files=2, scan_max_file_bytes=100),
                database=database,
                github=FakeGitHub(),  # type: ignore[arg-type]
                ollama=FakeOllama(),  # type: ignore[arg-type]
            )
            self.assertEqual(result.status, "incomplete")
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.files_eligible, 3)
            self.assertEqual(result.files_selected, 2)
            self.assertEqual(result.files_skipped, 2)
            history = database.history()
            self.assertEqual(history[0]["commit_sha"], "abc123")
            self.assertEqual(history[0]["status"], "incomplete")
            self.assertIn("size limit", history[0]["error"])
            file_rows = database.scan_files(history[0]["id"])
            self.assertEqual({row["status"] for row in file_rows}, {"analyzed", "skipped"})
            self.assertEqual(len(file_rows), 3)

    def test_malformed_model_response_is_rejected(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/chat":
                return httpx.Response(200, json={"message": {"content": "not-json"}})
            return httpx.Response(200, json={"models": []})

        client = OllamaClient(settings, transport=httpx.MockTransport(handler))
        with self.assertRaises(AssessmentValidationError):
            client.analyze(source="print('x')", relative_path="app.py")

    def test_timeout_retries_with_bounded_backoff(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=1, ollama_retry_backoff_seconds=0)
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise httpx.ReadTimeout("timed out", request=request)

        with self.assertRaisesRegex(OllamaUnavailable, "timeout"):
            OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="print('x')", relative_path="app.py")
        self.assertEqual(calls, 2)

    def test_connection_refusal_retries_and_is_sanitized(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=1, ollama_retry_backoff_seconds=0)
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            raise httpx.ConnectError("connection refused: secret-source-marker", request=request)

        with self.assertRaisesRegex(OllamaUnavailable, "connection-error") as error:
            OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="print('x')", relative_path="app.py")
        self.assertNotIn("secret-source-marker", str(error.exception))
        self.assertEqual(calls, 2)

    def test_retryable_http_error_then_success(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=1, ollama_retry_backoff_seconds=0)
        calls = 0
        valid = {"status": "clean", "summary": "No issue", "reasoning": "No evidence", "findings": [], "limitations": []}

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(503, json={"message": "temporary"})
            return httpx.Response(200, json={"message": {"content": json.dumps(valid)}})

        result = OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="print('x')", relative_path="app.py")
        self.assertEqual(result.status.value, "clean")
        self.assertEqual(calls, 2)

    def test_retryable_http_exhaustion_is_not_a_clean_assessment(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=1, ollama_retry_backoff_seconds=0)
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(429, json={"message": "busy"})

        with self.assertRaisesRegex(OllamaUnavailable, "http-429"):
            OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="print('x')", relative_path="app.py")
        self.assertEqual(calls, 2)

    def test_scan_lock_prevents_overlapping_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            repository_id = database.upsert_repository("acme/widget")
            first = database.start_scan(repository_id)
            with self.assertRaises(ScanAlreadyRunning):
                database.start_scan(repository_id)
            database.finish_scan(first, "incomplete", "stopped", error="test cleanup")
            second = database.start_scan(repository_id)
            database.finish_scan(second, "incomplete", "stopped", error="test cleanup")

    def test_scan_interruption_is_finalized_and_selected_files_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            database.upsert_repository("acme/widget")
            database.set_repository_selection("acme/widget", True)
            source = "print('x')\n"

            class FakeGitHub:
                def get_repository(self, full_name: str) -> GitHubRepository:
                    return GitHubRepository("acme/widget", "main", "test", False)

                def get_default_branch_sha(self, repository: GitHubRepository) -> str:
                    return "sha"

                def list_source_files(self, full_name: str, commit_sha: str, extensions: list[str]) -> tuple[list[GitHubTreeEntry], bool]:
                    return [GitHubTreeEntry("app.py", "file-sha", len(source.encode()))], False

                def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
                    return source

            class InterruptingOllama:
                def check_connectivity(self) -> bool:
                    return True

                def analyze(self, *, source: str, relative_path: str) -> SecurityAssessment:
                    raise KeyboardInterrupt

            with self.assertRaises(KeyboardInterrupt):
                scan_repository(
                    "acme/widget", settings=Settings(scan_max_files=1), database=database,
                    github=FakeGitHub(), ollama=InterruptingOllama(),  # type: ignore[arg-type]
                )
            scan = database.latest_scan("acme/widget")
            self.assertEqual(scan["status"], "incomplete")
            self.assertEqual(scan["files_skipped"], 1)
            self.assertIn("interrupted", scan["error"])
            self.assertEqual(database.scan_files(scan["id"])[0]["status"], "skipped")

    def test_schema_violation_retries_with_concise_correction_and_succeeds(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=1)
        requests: list[dict[str, object]] = []
        valid = {"status": "clean", "summary": "No evidence", "reasoning": "Inspected source", "findings": [], "limitations": []}

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(json.loads(request.content))
            content = '{"status":"clean"}' if len(requests) == 1 else json.dumps(valid)
            return httpx.Response(200, json={"message": {"content": content}})

        assessment = OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="print('x')", relative_path="app.py")
        self.assertEqual(assessment.status, "clean")
        self.assertEqual(len(requests), 2)
        self.assertIsInstance(requests[0]["format"], dict)
        self.assertEqual(requests[0]["format"]["type"], "object")
        retry_prompt = requests[1]["messages"][1]["content"]
        self.assertIn("failed validation", retry_prompt)
        self.assertEqual(retry_prompt.count("print('x')"), 1)

    def test_retry_exhaustion_is_not_converted_to_clean(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=1)
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200, json={"message": {"content": "{}"}})

        with self.assertRaises(AssessmentValidationError):
            OllamaClient(settings, transport=httpx.MockTransport(handler)).analyze(source="print('x')", relative_path="app.py")
        self.assertEqual(calls, 2)

    def test_representative_initializer_and_test_module_use_same_strict_contract(self) -> None:
        settings = Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0)
        responses: list[dict[str, object]] = []
        valid = {"status": "clean", "summary": "No evidence", "reasoning": "Inspected supplied source", "findings": [], "limitations": []}

        def handler(request: httpx.Request) -> httpx.Response:
            responses.append(json.loads(request.content))
            return httpx.Response(200, json={"message": {"content": json.dumps(valid)}})

        client = OllamaClient(settings, transport=httpx.MockTransport(handler))
        samples = {
            "backend/detectors/__init__.py": "\"\"\"Detector package.\"\"\"\nfrom .regex_detector import RegexDetector\n__all__ = [\"RegexDetector\"]\n",
            "backend/tests/test_pii_detector.py": "from backend.detectors.pii_detector import PIIDetector\n\ndef test_detects_email():\n    assert PIIDetector().detect(\"user@example.com\")\n",
        }
        for path, source in samples.items():
            assessment = client.analyze(source=source, relative_path=path)
            self.assertEqual(assessment.status.value, "clean")
        self.assertEqual(len(responses), 2)
        self.assertTrue(all(isinstance(request["format"], dict) for request in responses))

    def test_test_fixture_guidance_keeps_test_data_distinct_from_real_sinks(self) -> None:
        source = '''from sanitizers.masker import mask_value


def test_api_key_is_masked():
    value = "sk-test-not-a-credential"
    assert mask_value(value, "api_key") == "sk-t****ial"
'''
        response = {
            "status": "clean",
            "summary": "The supplied test fixture does not establish a vulnerability.",
            "reasoning": "The token-like value is used as an expected test input and is not sent to a sink in this file.",
            "findings": [],
            "limitations": ["The production implementation is outside this file."],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            prompt = json.loads(request.content)["messages"][1]["content"]
            self.assertIn("This is a test module or fixture", prompt)
            self.assertIn("synthetic emails, tokens, passwords", prompt)
            self.assertIn("real disclosure, execution", prompt)
            self.assertIn("status=incomplete merely because the production implementation", prompt)
            self.assertIn("backend/tests/test_masker.py", prompt)
            return httpx.Response(200, json={"message": {"content": json.dumps(response)}})

        assessment = OllamaClient(
            Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0),
            transport=httpx.MockTransport(handler),
        ).analyze(source=source, relative_path="backend/tests/test_masker.py")
        self.assertEqual(assessment.status.value, "clean")
        self.assertEqual(assessment.findings, [])

    def test_test_module_incomplete_status_is_preserved(self) -> None:
        response = {
            "status": "incomplete",
            "summary": "The test requires unavailable execution context.",
            "reasoning": "The supplied fixture does not establish whether the external test harness exposes the value.",
            "findings": [],
            "limitations": ["External test harness behavior is unavailable."],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"content": json.dumps(response)}})

        assessment = OllamaClient(
            Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0),
            transport=httpx.MockTransport(handler),
        ).analyze(source="def test_external_behavior():\n    assert external_value\n", relative_path="tests/test_external.py")
        self.assertEqual(assessment.status.value, "incomplete")
        self.assertEqual(assessment.findings, [])

    def test_partial_model_failure_marks_scan_incomplete_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.db")
            database.initialize()
            database.upsert_repository("acme/widget")
            database.set_repository_selection("acme/widget", True)

            class FakeGitHub:
                def get_repository(self, full_name: str) -> GitHubRepository:
                    return GitHubRepository("acme/widget", "main", "test", False)

                def get_default_branch_sha(self, repository: GitHubRepository) -> str:
                    return "sha"

                def list_source_files(self, full_name: str, commit_sha: str, extensions: list[str]) -> tuple[list[GitHubTreeEntry], bool]:
                    return [GitHubTreeEntry("bad.py", "1", 1), GitHubTreeEntry("good.py", "2", 1)], False

                def read_file(self, full_name: str, path: str, commit_sha: str) -> str:
                    return "print('x')"

            class PartialOllama:
                def check_connectivity(self) -> bool:
                    return True

                def analyze(self, *, source: str, relative_path: str) -> SecurityAssessment:
                    if relative_path == "bad.py":
                        raise AssessmentValidationError("schema-invalid response")
                    return SecurityAssessment(status="clean", summary="No evidence", reasoning="Inspected", findings=[], limitations=[])

            result = scan_repository(
                "acme/widget",
                settings=Settings(scan_max_files=2, scan_max_file_bytes=100),
                database=database,
                github=FakeGitHub(),  # type: ignore[arg-type]
                ollama=PartialOllama(),  # type: ignore[arg-type]
            )
            self.assertEqual(result.status, "incomplete")
            self.assertEqual(result.files_scanned, 1)
            self.assertIn("schema-invalid", result.errors[0])
            history = database.history()
            self.assertEqual(history[0]["status"], "incomplete")
            self.assertIn("bad.py", history[0]["error"])


if __name__ == "__main__":
    unittest.main()
