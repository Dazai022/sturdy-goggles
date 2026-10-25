from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4


SCHEMA_VERSION = 8


class ScanAlreadyRunning(ValueError):
    """Raised when another non-stale scan owns the repository lock."""


class Database:
    """Small SQLite persistence layer with transactional schema migration."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connection() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            current = int(row[0]) if row else 0
            if current < 1:
                connection.executescript(
                    """
                    CREATE TABLE repositories (
                        id TEXT PRIMARY KEY,
                        full_name TEXT NOT NULL UNIQUE,
                        default_branch TEXT,
                        description TEXT,
                        is_allowed INTEGER NOT NULL DEFAULT 0 CHECK (is_allowed IN (0, 1)),
                        metadata_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE scan_runs (
                        id TEXT PRIMARY KEY,
                        repository_id TEXT NOT NULL REFERENCES repositories(id),
                        status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed', 'incomplete')),
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        summary TEXT,
                        commit_sha TEXT,
                        error TEXT,
                        files_scanned INTEGER NOT NULL DEFAULT 0,
                        files_eligible INTEGER NOT NULL DEFAULT 0,
                        files_selected INTEGER NOT NULL DEFAULT 0,
                        files_failed INTEGER NOT NULL DEFAULT 0,
                        files_skipped INTEGER NOT NULL DEFAULT 0,
                        source_bytes INTEGER NOT NULL DEFAULT 0
                    );
                    CREATE TABLE findings (
                        id TEXT PRIMARY KEY,
                        scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
                        scanner TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        evidence TEXT NOT NULL,
                        remediation TEXT,
                        confidence TEXT NOT NULL DEFAULT 'confirmed',
                        affected_file TEXT,
                        line_start INTEGER,
                        line_end INTEGER,
                        reasoning TEXT,
                        verification_steps_json TEXT NOT NULL DEFAULT '[]',
                        attack_path TEXT,
                        affected_security_property TEXT,
                        attacker_prerequisites TEXT,
                        concrete_impact TEXT,
                        verification_status TEXT NOT NULL DEFAULT 'unverified' CHECK (verification_status IN ('unverified', 'supported', 'rejected')),
                        verification_reason TEXT,
                        verification_method TEXT
                    );
                    CREATE TABLE audit_events (
                        id TEXT PRIMARY KEY,
                        event_type TEXT NOT NULL,
                        repository_id TEXT REFERENCES repositories(id),
                        details TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL
                    );
                    CREATE INDEX findings_scan_idx ON findings(scan_run_id);
                    CREATE INDEX scans_repository_idx ON scan_runs(repository_id, started_at DESC);
                    CREATE TABLE scan_files (
                        id TEXT PRIMARY KEY,
                        scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
                        path TEXT NOT NULL,
                        sha TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('selected', 'analyzed', 'failed', 'skipped')),
                        error TEXT,
                        source_bytes INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        completed_at TEXT
                    );
                    CREATE INDEX scan_files_run_idx ON scan_files(scan_run_id, path);
                    CREATE TABLE proposals (
                        id TEXT PRIMARY KEY,
                        finding_id TEXT NOT NULL REFERENCES findings(id),
                        repository_id TEXT NOT NULL REFERENCES repositories(id),
                        target_file TEXT NOT NULL,
                        base_commit_sha TEXT NOT NULL,
                        proposed_diff TEXT NOT NULL DEFAULT '',
                        model_name TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        validation_status TEXT NOT NULL CHECK (validation_status IN ('proposed', 'invalid', 'needs_review')),
                        validation_errors TEXT,
                        rationale TEXT,
                        expected_behavior_change TEXT,
                        risks_json TEXT NOT NULL DEFAULT '[]',
                        validation_recommendations_json TEXT NOT NULL DEFAULT '[]',
                        diff_sha256 TEXT
                    );
                    CREATE INDEX proposals_finding_idx ON proposals(finding_id, created_at DESC);
                    DELETE FROM schema_version;
                    INSERT INTO schema_version(version) VALUES (7);
                    """
                )
                current = 7
            if current < 2:
                connection.executescript(
                    """
                    ALTER TABLE scan_runs ADD COLUMN commit_sha TEXT;
                    ALTER TABLE scan_runs ADD COLUMN error TEXT;
                    ALTER TABLE scan_runs ADD COLUMN files_scanned INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE findings ADD COLUMN affected_file TEXT;
                    ALTER TABLE findings ADD COLUMN line_start INTEGER;
                    ALTER TABLE findings ADD COLUMN line_end INTEGER;
                    UPDATE repositories SET is_allowed = 0;
                    UPDATE schema_version SET version = 2;
                    """
                )
                current = 2
            if current < 3:
                connection.executescript(
                    """
                    ALTER TABLE scan_runs ADD COLUMN files_eligible INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE scan_runs ADD COLUMN files_selected INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE scan_runs ADD COLUMN files_failed INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE scan_runs ADD COLUMN files_skipped INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE scan_runs ADD COLUMN source_bytes INTEGER NOT NULL DEFAULT 0;
                    CREATE TABLE scan_files (
                        id TEXT PRIMARY KEY,
                        scan_run_id TEXT NOT NULL REFERENCES scan_runs(id),
                        path TEXT NOT NULL,
                        sha TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('selected', 'analyzed', 'failed', 'skipped')),
                        error TEXT,
                        source_bytes INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        completed_at TEXT
                    );
                    CREATE INDEX scan_files_run_idx ON scan_files(scan_run_id, path);
                    UPDATE schema_version SET version = 3;
                    """
                )
            if current < 4:
                connection.executescript(
                    """
                    ALTER TABLE findings ADD COLUMN verification_status TEXT NOT NULL DEFAULT 'unverified'
                        CHECK (verification_status IN ('unverified', 'supported', 'rejected'));
                    ALTER TABLE findings ADD COLUMN verification_reason TEXT;
                    ALTER TABLE findings ADD COLUMN verification_method TEXT;
                    UPDATE schema_version SET version = 4;
                    """
                )
            if current < 5:
                connection.executescript(
                    """
                    ALTER TABLE findings ADD COLUMN reasoning TEXT;
                    ALTER TABLE findings ADD COLUMN verification_steps_json TEXT NOT NULL DEFAULT '[]';
                    UPDATE schema_version SET version = 5;
                    """
                )
            if current < 6:
                connection.executescript(
                    """
                    CREATE TABLE proposals (
                        id TEXT PRIMARY KEY,
                        finding_id TEXT NOT NULL REFERENCES findings(id),
                        repository_id TEXT NOT NULL REFERENCES repositories(id),
                        target_file TEXT NOT NULL,
                        base_commit_sha TEXT NOT NULL,
                        proposed_diff TEXT NOT NULL DEFAULT '',
                        model_name TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        validation_status TEXT NOT NULL CHECK (validation_status IN ('proposed', 'invalid', 'needs_review')),
                        validation_errors TEXT,
                        rationale TEXT,
                        expected_behavior_change TEXT,
                        risks_json TEXT NOT NULL DEFAULT '[]',
                        validation_recommendations_json TEXT NOT NULL DEFAULT '[]',
                        diff_sha256 TEXT
                    );
                    CREATE INDEX proposals_finding_idx ON proposals(finding_id, created_at DESC);
                    UPDATE schema_version SET version = 6;
                    """
                )
            if current < 7:
                connection.executescript(
                    """
                    ALTER TABLE findings ADD COLUMN attack_path TEXT;
                    ALTER TABLE findings ADD COLUMN affected_security_property TEXT;
                    ALTER TABLE findings ADD COLUMN attacker_prerequisites TEXT;
                    ALTER TABLE findings ADD COLUMN concrete_impact TEXT;
                    UPDATE schema_version SET version = 7;
                    """
                )
            if current < 8:
                connection.executescript(
                    """
                    CREATE TABLE scan_locks (
                        repository_id TEXT PRIMARY KEY REFERENCES repositories(id),
                        scan_id TEXT NOT NULL UNIQUE REFERENCES scan_runs(id),
                        acquired_at TEXT NOT NULL
                    );
                    UPDATE schema_version SET version = 8;
                    """
                )

    def upsert_repository(self, full_name: str, *, default_branch: str | None = None,
                          description: str | None = None, metadata_json: str = "{}") -> str:
        normalized = full_name.strip().lower()
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as connection:
            row = connection.execute("SELECT id FROM repositories WHERE full_name = ?", (normalized,)).fetchone()
            repository_id = str(row[0]) if row else str(uuid4())
            connection.execute(
                """INSERT INTO repositories(id, full_name, default_branch, description, metadata_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(full_name) DO UPDATE SET default_branch=excluded.default_branch,
                   description=excluded.description, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at""",
                (repository_id, normalized, default_branch, description, metadata_json, now, now),
            )
            return repository_id

    def set_repository_selection(self, full_name: str, selected: bool) -> None:
        with self.connection() as connection:
            updated = connection.execute(
                "UPDATE repositories SET is_allowed = ?, updated_at = ? WHERE full_name = ?",
                (int(selected), datetime.now(timezone.utc).isoformat(), full_name.strip().lower()),
            ).rowcount
            if updated != 1:
                raise KeyError(f"Repository is not persisted: {full_name}")

    def list_repositories(self) -> list[sqlite3.Row]:
        with self.connection() as connection:
            return list(connection.execute("SELECT * FROM repositories ORDER BY full_name"))

    def start_scan(self, repository_id: str, commit_sha: str = "") -> str:
        scan_id = str(uuid4())
        with self.connection() as connection:
            connection.execute(
                "INSERT INTO scan_runs(id, repository_id, status, started_at, commit_sha) VALUES (?, ?, 'running', ?, ?)",
                (scan_id, repository_id, datetime.now(timezone.utc).isoformat(), commit_sha),
            )
            try:
                connection.execute(
                    "INSERT INTO scan_locks(repository_id, scan_id, acquired_at) VALUES (?, ?, ?)",
                    (repository_id, scan_id, datetime.now(timezone.utc).isoformat()),
                )
            except sqlite3.IntegrityError as error:
                raise ScanAlreadyRunning("another scan is already running for this repository") from error
        return scan_id

    def recover_stale_scans(self, max_age_seconds: float) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(0.0, max_age_seconds))
        recovered = 0
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT id FROM scan_runs WHERE status = 'running' AND started_at < ?",
                (cutoff.isoformat(),),
            ).fetchall()
            for row in rows:
                scan_id = str(row[0])
                self._abort_scan_connection(connection, scan_id, "stale running scan recovered before a new scan")
                recovered += 1
        return recovered

    def abort_scan(self, scan_id: str, reason: str) -> None:
        with self.connection() as connection:
            self._abort_scan_connection(connection, scan_id, reason)

    @staticmethod
    def _abort_scan_connection(connection: sqlite3.Connection, scan_id: str, reason: str) -> None:
        connection.execute(
            "UPDATE scan_files SET status = 'skipped', error = ?, completed_at = ? WHERE scan_run_id = ? AND status = 'selected'",
            (reason[:1000], datetime.now(timezone.utc).isoformat(), scan_id),
        )
        stats = connection.execute(
            """SELECT COUNT(*),
                      SUM(CASE WHEN status = 'analyzed' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END),
                      SUM(CASE WHEN status = 'skipped' THEN 1 ELSE 0 END),
                      COALESCE(SUM(source_bytes), 0)
                 FROM scan_files WHERE scan_run_id = ?""",
            (scan_id,),
        ).fetchone()
        total, analyzed, failed, skipped, source_bytes = (int(value or 0) for value in stats)
        connection.execute(
            """UPDATE scan_runs SET status = 'incomplete', completed_at = ?,
               summary = ?, error = ?, files_scanned = ?, files_eligible = ?, files_selected = ?,
               files_failed = ?, files_skipped = ?, source_bytes = ? WHERE id = ?""",
            (
                datetime.now(timezone.utc).isoformat(),
                f"Eligible {total}; selected {total}; analyzed {analyzed}; failed {failed}; skipped {skipped}; scan interrupted; this is not a proof of repository security.",
                reason[:4000], analyzed, total, total, failed, skipped, source_bytes, scan_id,
            ),
        )
        connection.execute("DELETE FROM scan_locks WHERE scan_id = ?", (scan_id,))

    def finish_scan(self, scan_id: str, status: str, summary: str, *, error: str | None = None,
                    files_scanned: int = 0, files_eligible: int = 0, files_selected: int = 0,
                    files_failed: int = 0, files_skipped: int = 0, source_bytes: int = 0) -> None:
        if status not in {"complete", "failed", "incomplete"}:
            raise ValueError(f"Invalid terminal scan status: {status}")
        with self.connection() as connection:
            connection.execute(
                """UPDATE scan_runs SET status = ?, completed_at = ?, summary = ?, error = ?, files_scanned = ?,
                   files_eligible = ?, files_selected = ?, files_failed = ?, files_skipped = ?, source_bytes = ?
                   WHERE id = ?""",
                (status, datetime.now(timezone.utc).isoformat(), summary, error, files_scanned, files_eligible,
                 files_selected, files_failed, files_skipped, source_bytes, scan_id),
            )
            connection.execute("DELETE FROM scan_locks WHERE scan_id = ?", (scan_id,))

    def set_scan_commit(self, scan_id: str, commit_sha: str) -> None:
        with self.connection() as connection:
            connection.execute("UPDATE scan_runs SET commit_sha = ? WHERE id = ?", (commit_sha, scan_id))

    def add_finding(self, scan_id: str, *, scanner: str, severity: str, title: str, evidence: str,
                    remediation: str | None, confidence: str, affected_file: str, line_start: int, line_end: int,
                    reasoning: str | None = None, verification_steps_json: str = "[]",
                     attack_path: str | None = None, affected_security_property: str | None = None,
                     attacker_prerequisites: str | None = None, concrete_impact: str | None = None,
                    verification_status: str = "unverified", verification_reason: str | None = None,
                    verification_method: str | None = None) -> str:
        if verification_status not in {"unverified", "supported", "rejected"}:
            raise ValueError(f"Invalid finding verification status: {verification_status}")
        finding_id = str(uuid4())
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO findings(id, scan_run_id, scanner, severity, title, evidence, remediation, confidence,
                   affected_file, line_start, line_end, reasoning, verification_steps_json, attack_path,
                   affected_security_property, attacker_prerequisites, concrete_impact, verification_status,
                   verification_reason, verification_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (finding_id, scan_id, scanner, severity, title, evidence, remediation, confidence,
                 affected_file, line_start, line_end, reasoning, verification_steps_json, attack_path,
                 affected_security_property, attacker_prerequisites, concrete_impact, verification_status,
                 verification_reason, verification_method),
            )
        return finding_id

    def update_finding_verification(self, finding_id: str, *, status: str, reason: str, method: str) -> None:
        if status not in {"unverified", "supported", "rejected"}:
            raise ValueError(f"Invalid finding verification status: {status}")
        with self.connection() as connection:
            connection.execute(
                "UPDATE findings SET verification_status = ?, verification_reason = ?, verification_method = ? WHERE id = ?",
                (status, reason, method, finding_id),
            )

    def update_finding_verification_note(self, finding_id: str, *, reason: str, method: str) -> None:
        """Record a later verification observation without changing historical status."""
        with self.connection() as connection:
            connection.execute(
                "UPDATE findings SET verification_reason = ?, verification_method = ? WHERE id = ?",
                (reason, method, finding_id),
            )

    def findings(self, scan_id: str) -> list[sqlite3.Row]:
        with self.connection() as connection:
            return list(connection.execute("SELECT * FROM findings WHERE scan_run_id = ? ORDER BY affected_file, line_start, id", (scan_id,)))

    def finding(self, finding_id: str) -> sqlite3.Row | None:
        with self.connection() as connection:
            return connection.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()

    def scan(self, scan_id: str) -> sqlite3.Row | None:
        with self.connection() as connection:
            return connection.execute(
                "SELECT s.*, r.full_name FROM scan_runs s JOIN repositories r ON r.id = s.repository_id WHERE s.id = ?",
                (scan_id,),
            ).fetchone()

    def latest_scan(self, repository: str | None = None) -> sqlite3.Row | None:
        with self.connection() as connection:
            if repository:
                return connection.execute(
                    """SELECT s.*, r.full_name FROM scan_runs s JOIN repositories r ON r.id = s.repository_id
                       WHERE r.full_name = ? ORDER BY s.started_at DESC LIMIT 1""", (repository.strip().lower(),)
                ).fetchone()
            return connection.execute(
                """SELECT s.*, r.full_name FROM scan_runs s JOIN repositories r ON r.id = s.repository_id
                   ORDER BY s.started_at DESC LIMIT 1"""
            ).fetchone()

    def add_scan_file(self, scan_id: str, *, path: str, sha: str, size: int, status: str = "selected") -> str:
        if status not in {"selected", "analyzed", "failed", "skipped"}:
            raise ValueError(f"Invalid scan-file status: {status}")
        file_id = str(uuid4())
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO scan_files(id, scan_run_id, path, sha, size, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (file_id, scan_id, path, sha, size, status, datetime.now(timezone.utc).isoformat()),
            )
        return file_id

    def finish_scan_file(self, file_id: str, status: str, *, error: str | None = None, source_bytes: int = 0) -> None:
        if status not in {"analyzed", "failed", "skipped"}:
            raise ValueError(f"Invalid terminal scan-file status: {status}")
        with self.connection() as connection:
            connection.execute(
                "UPDATE scan_files SET status = ?, error = ?, source_bytes = ?, completed_at = ? WHERE id = ?",
                (status, error, source_bytes, datetime.now(timezone.utc).isoformat(), file_id),
            )

    def scan_files(self, scan_id: str) -> list[sqlite3.Row]:
        with self.connection() as connection:
            return list(connection.execute("SELECT * FROM scan_files WHERE scan_run_id = ? ORDER BY path", (scan_id,)))

    def history(self, limit: int = 20) -> list[sqlite3.Row]:
        with self.connection() as connection:
            return list(connection.execute(
                """SELECT s.*, r.full_name FROM scan_runs s JOIN repositories r ON r.id = s.repository_id
                   ORDER BY s.started_at DESC LIMIT ?""", (limit,)
            ))

    def add_proposal(self, *, finding_id: str, repository_id: str, target_file: str, base_commit_sha: str,
                     proposed_diff: str, model_name: str, validation_status: str,
                     validation_errors: str | None = None, rationale: str | None = None,
                     expected_behavior_change: str | None = None, risks_json: str = "[]",
                     validation_recommendations_json: str = "[]", diff_sha256: str | None = None) -> str:
        if validation_status not in {"proposed", "invalid", "needs_review"}:
            raise ValueError(f"Invalid proposal validation status: {validation_status}")
        proposal_id = str(uuid4())
        with self.connection() as connection:
            connection.execute(
                """INSERT INTO proposals(id, finding_id, repository_id, target_file, base_commit_sha, proposed_diff,
                   model_name, created_at, validation_status, validation_errors, rationale, expected_behavior_change,
                   risks_json, validation_recommendations_json, diff_sha256)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (proposal_id, finding_id, repository_id, target_file, base_commit_sha, proposed_diff, model_name,
                 datetime.now(timezone.utc).isoformat(), validation_status, validation_errors, rationale,
                 expected_behavior_change, risks_json, validation_recommendations_json, diff_sha256),
            )
        return proposal_id

    def proposal(self, proposal_id: str) -> sqlite3.Row | None:
        with self.connection() as connection:
            return connection.execute(
                """SELECT p.*, r.full_name FROM proposals p JOIN repositories r ON r.id = p.repository_id
                   WHERE p.id = ?""", (proposal_id,)
            ).fetchone()

    def proposals(self, limit: int = 50) -> list[sqlite3.Row]:
        with self.connection() as connection:
            return list(connection.execute(
                """SELECT p.*, r.full_name FROM proposals p JOIN repositories r ON r.id = p.repository_id
                   ORDER BY p.created_at DESC LIMIT ?""", (limit,)
            ))
