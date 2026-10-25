from __future__ import annotations

from dataclasses import dataclass, field
import json

from reposentinel.config import Settings
from reposentinel.db import Database, ScanAlreadyRunning
from reposentinel.github import GitHubClient, GitHubError
from reposentinel.llm import AssessmentValidationError, OllamaClient, OllamaUnavailable, assessment_incomplete_diagnostic
from reposentinel.verification import verify_finding_evidence


@dataclass
class ScanResult:
    repository: str
    status: str
    commit_sha: str | None
    files_scanned: int
    findings: int
    summary: str
    errors: list[str] = field(default_factory=list)
    files_eligible: int = 0
    files_selected: int = 0
    files_failed: int = 0
    files_skipped: int = 0
    source_bytes: int = 0


def scan_repository(
    full_name: str,
    *,
    settings: Settings,
    database: Database,
    github: GitHubClient,
    ollama: OllamaClient,
) -> ScanResult:
    normalized = full_name.strip().lower()
    row = next((item for item in database.list_repositories() if item["full_name"] == normalized), None)
    if row is None or not bool(row["is_allowed"]):
        raise PermissionError(f"Repository '{full_name}' is not selected in the local allowlist")

    database.recover_stale_scans(settings.scan_stale_after_seconds)
    scan_id = database.start_scan(str(row["id"]))
    commit_sha: str | None = None
    errors: list[str] = []
    files_scanned = 0
    findings = 0
    files_failed = 0
    files_skipped = 0
    files_eligible = 0
    files_selected = 0
    source_bytes = 0
    try:
        repository = github.get_repository(normalized)
        commit_sha = github.get_default_branch_sha(repository)
        database.set_scan_commit(scan_id, commit_sha)
        assert commit_sha is not None
        database.upsert_repository(
            repository.full_name,
            default_branch=repository.default_branch,
            description=repository.description,
        )
        if not ollama.check_connectivity():
            raise OllamaUnavailable("Ollama is unavailable; no LLM assessment was performed")
        entries, truncated = github.list_source_files(normalized, commit_sha, settings.supported_source_extensions)
        files_eligible = len(entries)
        if truncated:
            errors.append("GitHub returned a truncated repository tree")
        selected_entries = entries[:settings.scan_max_files]
        files_selected = len(selected_entries)
        if files_eligible > files_selected:
            errors.append(f"Source file limit reached: {files_selected} of {files_eligible} eligible files selected")
        selected_ids: dict[str, str] = {}
        for index, entry in enumerate(entries):
            if index >= files_selected:
                skipped_id = database.add_scan_file(scan_id, path=entry.path, sha=entry.sha, size=entry.size, status="skipped")
                database.finish_scan_file(skipped_id, "skipped", error="source file limit reached")
                files_skipped += 1
            else:
                selected_ids[entry.path] = database.add_scan_file(scan_id, path=entry.path, sha=entry.sha, size=entry.size)
        for entry in selected_entries:
            file_id = selected_ids[entry.path]
            current_bytes = 0
            if entry.size > settings.scan_max_file_bytes:
                error = "file exceeds configured per-file size limit"
                database.finish_scan_file(file_id, "skipped", error=error)
                errors.append(f"Skipped {entry.path}: {error}")
                files_skipped += 1
                continue
            if entry.size and source_bytes + entry.size > settings.scan_max_source_bytes:
                error = "total source-byte limit reached"
                database.finish_scan_file(file_id, "skipped", error=error)
                errors.append(f"Skipped {entry.path}: {error}")
                files_skipped += 1
                continue
            try:
                source = github.read_file(normalized, entry.path, commit_sha)
                current_bytes = len(source.encode("utf-8"))
                if current_bytes > settings.scan_max_file_bytes:
                    error = "decoded file exceeds configured per-file size limit"
                    database.finish_scan_file(file_id, "skipped", error=error, source_bytes=current_bytes)
                    errors.append(f"Skipped {entry.path}: {error}")
                    files_skipped += 1
                    continue
                if source_bytes + current_bytes > settings.scan_max_source_bytes:
                    error = "total source-byte limit reached"
                    database.finish_scan_file(file_id, "skipped", error=error, source_bytes=current_bytes)
                    errors.append(f"Skipped {entry.path}: {error}")
                    files_skipped += 1
                    continue
                source_bytes += current_bytes
                assessment = ollama.analyze(source=source, relative_path=entry.path)
                if assessment.status.value == "incomplete":
                    error = assessment_incomplete_diagnostic(assessment)
                    database.finish_scan_file(file_id, "failed", error=error, source_bytes=current_bytes)
                    errors.append(f"{entry.path}: {error}")
                    files_failed += 1
                    continue
                files_scanned += 1
                database.finish_scan_file(file_id, "analyzed", source_bytes=current_bytes)
                for finding in assessment.findings:
                    verification = verify_finding_evidence(
                        finding, source=source, relative_path=entry.path
                    )
                    finding_id = database.add_finding(
                        scan_id,
                        scanner="ollama",
                        severity=finding.severity,
                        title=finding.title,
                        evidence=finding.evidence,
                        remediation=finding.recommended_remediation,
                        confidence="confirmed" if assessment.status.value == "confirmed" else "possible",
                        affected_file=finding.affected_file,
                        line_start=finding.line_start,
                        line_end=finding.line_end,
                        reasoning=finding.reasoning,
                        verification_steps_json=json.dumps(finding.verification_steps),
                        attack_path=finding.attack_path,
                        affected_security_property=finding.affected_security_property,
                        attacker_prerequisites=finding.attacker_prerequisites,
                        concrete_impact=finding.concrete_impact,
                        verification_status=verification.status.value,
                        verification_reason=verification.reason,
                        verification_method=verification.method,
                    )
                    # Keep unsupported model claims visible for review, but never treat them as supported.
                    findings += 1
            except (GitHubError, AssessmentValidationError, OllamaUnavailable, ValueError) as error:
                database.finish_scan_file(file_id, "failed", error=str(error)[:1000], source_bytes=current_bytes)
                errors.append(f"{entry.path}: {error}")
                files_failed += 1
        if files_eligible == 0:
            errors.append("No eligible source files found")
        status = "incomplete" if errors or files_failed or files_skipped else "complete"
        summary = (
            f"Eligible {files_eligible}; selected {files_selected}; analyzed {files_scanned}; "
            f"failed {files_failed}; skipped {files_skipped}; recorded {findings} findings; "
            "this is not a proof of repository security."
        )
        database.finish_scan(
            scan_id, status, summary, error="; ".join(errors)[:4000] or None,
            files_scanned=files_scanned, files_eligible=files_eligible, files_selected=files_selected,
            files_failed=files_failed, files_skipped=files_skipped, source_bytes=source_bytes,
        )
        return ScanResult(normalized, status, commit_sha, files_scanned, findings, summary, errors,
                          files_eligible, files_selected, files_failed, files_skipped, source_bytes)
    except KeyboardInterrupt:
        database.abort_scan(scan_id, "scan interrupted by user")
        raise
    except (GitHubError, OllamaUnavailable, ValueError) as error:
        message = str(error)
        database.finish_scan(
            scan_id, "incomplete", "Scan could not complete; no security conclusion was made.", error=message,
            files_scanned=files_scanned, files_eligible=files_eligible, files_selected=files_selected,
            files_failed=files_failed, files_skipped=files_skipped, source_bytes=source_bytes,
        )
        return ScanResult(normalized, "incomplete", commit_sha, files_scanned, findings, "Scan incomplete", [message],
                          files_eligible, files_selected, files_failed, files_skipped, source_bytes)
    except Exception as error:
        database.abort_scan(scan_id, f"unexpected scan failure: {type(error).__name__}")
        raise
