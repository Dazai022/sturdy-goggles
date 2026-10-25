from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from reposentinel.llm import SecurityFinding


class FindingVerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    SUPPORTED = "supported"
    REJECTED = "rejected"


@dataclass(frozen=True)
class EvidenceVerification:
    status: FindingVerificationStatus
    reason: str
    method: str = "snapshot-evidence-check"


def verify_finding_evidence(
    finding: SecurityFinding,
    *,
    source: str,
    relative_path: str,
) -> EvidenceVerification:
    """Independently verify a citation against the exact source text supplied to the LLM.

    ``supported`` means the citation is anchored to the snapshot. It does not mean the
    claimed vulnerability is proven; that requires human review and appropriate tests.
    """
    if finding.affected_file != relative_path:
        return EvidenceVerification(FindingVerificationStatus.REJECTED, "finding file does not match the analyzed snapshot")
    lines = source.splitlines()
    if finding.line_start < 1 or finding.line_end < finding.line_start or finding.line_end > len(lines):
        return EvidenceVerification(FindingVerificationStatus.REJECTED, "finding line range is outside the analyzed snapshot")
    cited = "\n".join(lines[finding.line_start - 1:finding.line_end])
    if " ".join(finding.evidence.split()) not in " ".join(cited.split()):
        return EvidenceVerification(FindingVerificationStatus.REJECTED, "finding evidence is not present in the cited line range")
    return EvidenceVerification(
        FindingVerificationStatus.SUPPORTED,
        "file, line range, and evidence match the pinned source snapshot; vulnerability claim remains unconfirmed",
    )
