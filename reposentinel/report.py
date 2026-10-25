from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from reposentinel.db import Database
from reposentinel.github import GitHubClient, GitHubError


def verify_persisted_findings(database: Database, scan: Any, github: GitHubClient | None) -> list[str]:
    """Recheck historical citations against the scan's pinned commit when possible."""
    limitations: list[str] = []
    findings = database.findings(str(scan["id"]))
    if not findings:
        return limitations
    if github is None:
        limitations.append("Finding citations remain unverified because no GitHub token is configured.")
        return limitations
    cache: dict[str, str] = {}
    for finding in findings:
        path = str(finding["affected_file"] or "")
        try:
            if path not in cache:
                cache[path] = github.read_file(str(scan["full_name"]), path, str(scan["commit_sha"] or ""))
            source = cache[path]
            lines = source.splitlines()
            if finding["line_start"] is None or finding["line_end"] is None:
                reason = "invalid line range: finding has no complete line reference"
            elif not (1 <= int(finding["line_start"]) <= int(finding["line_end"]) <= len(lines)):
                reason = "invalid line range: outside the pinned source snapshot"
            else:
                cited = "\n".join(lines[int(finding["line_start"]) - 1:int(finding["line_end"])])
                if " ".join(str(finding["evidence"]).split()) in " ".join(cited.split()):
                    reason = "file, line range, and evidence match the pinned source snapshot; vulnerability claim remains unconfirmed"
                else:
                    reason = "evidence mismatch: evidence is not present in the cited lines of the pinned source snapshot"
            database.update_finding_verification_note(
                str(finding["id"]), reason=reason, method="pinned-commit-evidence-check"
            )
        except (GitHubError, ValueError, TypeError) as error:
            reason = "missing file or snapshot retrieval failure: " + str(error)[:300]
            database.update_finding_verification_note(
                str(finding["id"]), reason=reason, method="pinned-commit-evidence-check"
            )
            limitations.append(f"Could not verify {path}: {str(error)[:300]}")
    return limitations


def build_report(database: Database, scan_id: str | None = None, *, github: GitHubClient | None = None) -> dict[str, Any]:
    scan = database.scan(scan_id) if scan_id else database.latest_scan()
    if scan is None:
        raise ValueError("No persisted scan is available")
    limitations = [
        "This report is not proof that the repository is secure.",
        "supported means only that the cited evidence matches the pinned snapshot; it is not a confirmed vulnerability.",
    ]
    limitations.extend(verify_persisted_findings(database, scan, github))
    rows = database.findings(str(scan["id"]))
    files = database.scan_files(str(scan["id"]))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": str(scan["full_name"]),
        "commit_sha": scan["commit_sha"],
        "scan": {
            "id": scan["id"],
            "status": scan["status"],
            "started_at": scan["started_at"],
            "completed_at": scan["completed_at"],
            "summary": scan["summary"],
            "error": scan["error"],
            "eligible": scan["files_eligible"],
            "selected": scan["files_selected"],
            "analyzed": scan["files_scanned"],
            "failed": scan["files_failed"],
            "skipped": scan["files_skipped"],
            "source_bytes": scan["source_bytes"],
        },
        "files": [
            {"path": row["path"], "sha": row["sha"], "size": row["size"], "status": row["status"], "error": row["error"], "source_bytes": row["source_bytes"]}
            for row in files
        ],
        "findings": [
            {
                "id": row["id"], "scanner": row["scanner"], "severity": row["severity"], "confidence": row["confidence"],
                "title": row["title"], "file": row["affected_file"], "line_start": row["line_start"], "line_end": row["line_end"],
                "evidence": row["evidence"], "explanation": row["reasoning"] or row["remediation"],
                "recommended_remediation": row["remediation"],
                "attack_path": row["attack_path"],
                "affected_security_property": row["affected_security_property"],
                "attacker_prerequisites": row["attacker_prerequisites"],
                "concrete_impact": row["concrete_impact"],
                "verification_status": row["verification_status"], "verification_reason": row["verification_reason"],
                "verification_method": row["verification_method"],
                "next_steps": (json.loads(row["verification_steps_json"]) if row["verification_steps_json"] else []) + [
                    "Review the cited code and reproduce the behavior with a focused test.",
                    "Do not treat model confidence or supported citation status as proof of a vulnerability.",
                ],
            }
            for row in rows
        ],
        "limitations": limitations,
    }
