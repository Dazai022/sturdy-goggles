from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from reposentinel.config import Settings
from reposentinel.db import Database
from reposentinel.github import GitHubClient, GitHubError
from reposentinel.llm import AssessmentValidationError, OllamaClient, OllamaUnavailable, PatchProposal


class ProposalError(RuntimeError):
    """Safe, user-facing proposal failure."""


class ProposalEligibilityError(ProposalError):
    pass


@dataclass(frozen=True)
class DiffValidation:
    valid: bool
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProposalResult:
    proposal_id: str
    status: str
    finding_id: str
    target_file: str
    base_commit_sha: str
    errors: list[str] = field(default_factory=list)


_HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)")


def validate_unified_diff(diff: str, *, target_file: str, source: str, max_bytes: int) -> DiffValidation:
    errors: list[str] = []
    if not diff.strip():
        return DiffValidation(False, ["proposed diff is empty"])
    if len(diff.encode("utf-8")) > max_bytes:
        errors.append("proposed diff exceeds the configured output-size limit")
    if "\x00" in diff or "GIT binary patch" in diff or "Binary files" in diff:
        errors.append("binary patches are not allowed")
    lines = diff.splitlines()
    if len(lines) < 3 or not lines[0].startswith("diff --git ") or lines[1].startswith("@@"):
        errors.append("diff is missing a standard unified-diff header")
    elif len(lines[0].split()) != 4:
        errors.append("diff git header is malformed")
    parsed_paths: list[str] = []
    for header, prefix in (("--- ", "a/"), ("+++ ", "b/")):
        matching = [line[len(header):].split("\t", 1)[0] for line in lines if line.startswith(header)]
        if len(matching) != 1:
            errors.append(f"diff must contain exactly one {header.strip()} path")
            continue
        path = _safe_diff_path(matching[0], prefix)
        if path is None:
            errors.append("diff contains an absolute or traversal path")
        else:
            parsed_paths.append(path)
    if len(parsed_paths) == 2 and (parsed_paths[0] != target_file or parsed_paths[1] != target_file):
        errors.append("diff targets a file other than the supported finding file")
    if len(parsed_paths) == 2 and parsed_paths[0] != parsed_paths[1]:
        errors.append("diff source and destination paths differ")
    if len(lines) >= 1 and lines[0].startswith("diff --git ") and len(lines[0].split()) == 4:
        git_paths = [_safe_diff_path(lines[0].split()[2], "a/"), _safe_diff_path(lines[0].split()[3], "b/")]
        if git_paths != [target_file, target_file]:
            errors.append("diff git header targets an unexpected file")

    source_lines = source.splitlines()
    hunks = [(index, line) for index, line in enumerate(lines) if line.startswith("@@ ")]
    if not hunks:
        errors.append("diff contains no hunks")
    changed = False
    for hunk_index, (line_index, header) in enumerate(hunks):
        match = _HUNK_RE.fullmatch(header)
        if match is None:
            errors.append(f"invalid hunk header: {header[:120]}")
            continue
        old_start = int(match.group(1))
        old_count = int(match.group(2) or "1")
        old_seen = new_seen = 0
        position = old_start - 1
        if old_count == 0 and old_start > len(source_lines) + 1:
            errors.append("diff insertion point is outside the pinned source snapshot")
        if old_count > 0 and old_start > len(source_lines):
            errors.append("diff hunk starts outside the pinned source snapshot")
        end = hunks[hunk_index + 1][0] if hunk_index + 1 < len(hunks) else len(lines)
        for body_line in lines[line_index + 1:end]:
            if body_line.startswith("\\ No newline at end of file"):
                continue
            if not body_line or body_line[0] not in " +-":
                errors.append("diff contains a malformed hunk line")
                continue
            marker, content = body_line[0], body_line[1:]
            if marker in " -":
                old_seen += 1
                if position >= len(source_lines) or source_lines[position].rstrip("\r\n") != content:
                    errors.append("diff hunk does not apply to the pinned source snapshot")
                position += 1
            if marker in " +":
                new_seen += 1
            if marker in "+-":
                changed = True
        if old_seen != old_count:
            errors.append("diff hunk source-line count does not match its header")
        # The destination count is validated from the body independently of source application.
        new_count = int(match.group(4) or "1")
        if new_seen != new_count:
            errors.append("diff hunk destination-line count does not match its header")
    if not changed:
        errors.append("diff contains no added or removed lines")
    return DiffValidation(not errors, errors)


def _safe_diff_path(path: str, prefix: str) -> str | None:
    if path == "/dev/null":
        return None
    if path.startswith(prefix):
        path = path[len(prefix):]
    if not path or path.startswith(("/", "\\")) or "\\" in path:
        return None
    parts = PurePosixPath(path).parts
    if any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]:
        return None
    return "/".join(parts)


def _verify_row_evidence(row: object, source: str, target_file: str) -> None:
    path = str(row["affected_file"] or "")  # type: ignore[index]
    start = row["line_start"]  # type: ignore[index]
    end = row["line_end"]  # type: ignore[index]
    if path != target_file or not isinstance(start, int) or not isinstance(end, int):
        raise ProposalEligibilityError("finding citation is incomplete or does not identify the target file")
    lines = source.splitlines()
    if start < 1 or end < start or end > len(lines):
        raise ProposalEligibilityError("finding line range does not match the pinned source snapshot")
    cited = "\n".join(lines[start - 1:end])
    if " ".join(str(row["evidence"]).split()) not in " ".join(cited.split()):  # type: ignore[index]
        raise ProposalEligibilityError("finding evidence is not present in the pinned source snapshot")


def propose_finding(
    finding_id: str,
    *,
    settings: Settings,
    database: Database,
    github: GitHubClient,
    ollama: OllamaClient,
    expected_base_commit: str | None = None,
) -> ProposalResult:
    finding = database.finding(finding_id)
    if finding is None:
        raise ProposalEligibilityError(f"Finding '{finding_id}' was not found")
    if finding["verification_status"] != "supported":
        raise ProposalEligibilityError(
            f"Finding '{finding_id}' is {finding['verification_status']}; only independently supported findings may receive proposals"
        )
    scan = database.scan(str(finding["scan_run_id"]))
    if scan is None or not scan["commit_sha"]:
        raise ProposalEligibilityError("Finding has no pinned repository snapshot")
    base_commit = str(scan["commit_sha"])
    if expected_base_commit is not None and expected_base_commit != base_commit:
        raise ProposalEligibilityError("base commit does not match the finding's pinned scan commit")
    target_file = str(finding["affected_file"] or "")
    if not target_file or target_file.startswith(("/", "\\")) or ".." in target_file.split("/"):
        raise ProposalEligibilityError("finding target file is unsafe")
    try:
        source = github.read_file(str(scan["full_name"]), target_file, base_commit)
    except (GitHubError, ValueError) as error:
        raise ProposalEligibilityError(f"could not retrieve the pinned source snapshot: {error}") from error
    _verify_row_evidence(finding, source, target_file)
    try:
        model_output = ollama.propose_patch(
            source=source,
            relative_path=target_file,
            finding_title=str(finding["title"]),
            finding_evidence=str(finding["evidence"]),
            finding_reasoning=str(finding["reasoning"] or ""),
            finding_remediation=str(finding["remediation"] or ""),
        )
    except (AssessmentValidationError, OllamaUnavailable, ValueError) as error:
        proposal_id = database.add_proposal(
            finding_id=finding_id, repository_id=str(scan["repository_id"]), target_file=target_file,
            base_commit_sha=base_commit, proposed_diff="", model_name=settings.ollama_model,
            validation_status="invalid", validation_errors=str(error)[:2000],
        )
        return ProposalResult(proposal_id, "invalid", finding_id, target_file, base_commit, [str(error)])
    validation = validate_unified_diff(
        model_output.proposed_diff, target_file=target_file, source=source, max_bytes=settings.proposal_max_diff_bytes
    )
    status = "proposed" if validation.valid else "invalid"
    errors = validation.errors
    proposal_id = database.add_proposal(
        finding_id=finding_id, repository_id=str(scan["repository_id"]), target_file=target_file,
        base_commit_sha=base_commit, proposed_diff=model_output.proposed_diff, model_name=settings.ollama_model,
        validation_status=status, validation_errors="; ".join(errors)[:2000] or None,
        rationale=model_output.rationale, expected_behavior_change=model_output.expected_behavior_change,
        risks_json=json.dumps(model_output.risks),
        validation_recommendations_json=json.dumps(model_output.validation_recommendations),
        diff_sha256=hashlib.sha256(model_output.proposed_diff.encode("utf-8")).hexdigest(),
    )
    return ProposalResult(proposal_id, status, finding_id, target_file, base_commit, errors)
