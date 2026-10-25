import json
import unittest
from pathlib import Path

import httpx

from reposentinel.config import Settings
from reposentinel.llm import OllamaClient


class SyntheticDemoTests(unittest.TestCase):
    def test_password_logging_fixture_produces_source_grounded_finding(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "vulnerable_password_logging.py"
        source = fixture.read_text(encoding="utf-8")
        response = {
            "status": "possible",
            "summary": "A request password is written to application output.",
            "reasoning": "The source reads a request password and passes it directly to print.",
            "findings": [{
                "title": "Sensitive password logged",
                "severity": "high",
                "confidence": 0.98,
                "affected_file": "tests/fixtures/vulnerable_password_logging.py",
                "line_start": 3,
                "line_end": 3,
                "evidence": "    print(password)",
                "reasoning": "The password value is sent directly to the process output.",
                "recommended_remediation": "Remove the password from logs and redact sensitive values before logging.",
                "verification_steps": ["Exercise the handler with a test password and inspect captured output."],
                "attack_path": "A caller supplies a password that reaches the print call and is retained by process logging.",
                "affected_security_property": "confidentiality",
                "attacker_prerequisites": "Ability to submit a request containing a password.",
                "concrete_impact": "The password can be exposed to anyone with access to the process output or logs.",
            }],
            "limitations": [],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": {"content": json.dumps(response)}})

        assessment = OllamaClient(
            Settings(ollama_endpoint="http://127.0.0.1:11434", ollama_max_retries=0),
            transport=httpx.MockTransport(handler),
        ).analyze(source=source, relative_path="tests/fixtures/vulnerable_password_logging.py")

        self.assertEqual(assessment.status.value, "possible")
        self.assertEqual(len(assessment.findings), 1)
        self.assertEqual(assessment.findings[0].line_start, 3)
        self.assertEqual(assessment.findings[0].evidence, "    print(password)")


if __name__ == "__main__":
    unittest.main()
