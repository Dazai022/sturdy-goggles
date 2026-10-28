from __future__ import annotations

from functools import lru_cache
import hmac
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict

from reposentinel.config import Settings, get_settings
from reposentinel.db import Database
from reposentinel.report import build_report


class RepositoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str
    default_branch: str | None
    is_allowed: bool


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    repository: str
    status: str
    commit_sha: str | None
    eligible: int
    selected: int
    analyzed: int
    failed: int
    skipped: int
    findings: int | None
    error: str | None


bearer = HTTPBearer(auto_error=False)


def _row_to_scan(row: object) -> ScanResponse:
    values = dict(row)  # type: ignore[arg-type]
    return ScanResponse(
        id=str(values["id"]),
        repository=str(values["full_name"]),
        status=str(values["status"]),
        commit_sha=values.get("commit_sha"),
        eligible=int(values["files_eligible"] or 0),
        selected=int(values["files_selected"] or 0),
        analyzed=int(values["files_scanned"] or 0),
        failed=int(values["files_failed"] or 0),
        skipped=int(values["files_skipped"] or 0),
        findings=int(values["findings_count"]) if values.get("findings_count") is not None else None,
        error=values.get("error"),
    )


def create_app(*, settings: Settings | None = None, database: Database | None = None) -> FastAPI:
    """Create the authenticated, read-only local API over persisted scan data.

    This is a local foundation, not production multi-user authentication. A deployment
    must replace the shared token with user/session authorization before exposing it remotely.
    """

    runtime_settings = settings or get_settings()
    runtime_database = database or Database(runtime_settings.database_path)
    runtime_database.initialize()
    configured_token = runtime_settings.api_token.get_secret_value() if runtime_settings.api_token else None

    app = FastAPI(title="SentraForge AI API", version="0.1.0", docs_url="/docs")

    def require_api_token(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)],
    ) -> None:
        if not configured_token:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="API token is not configured")
        supplied = credentials.credentials if credentials else ""
        if not hmac.compare_digest(supplied, configured_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API credentials")

    auth = Depends(require_api_token)

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "read_only": True, "api_token_configured": bool(configured_token)}

    @app.get("/api/v1/repositories", response_model=list[RepositoryResponse], dependencies=[auth])
    def repositories() -> list[RepositoryResponse]:
        return [
            RepositoryResponse(
                full_name=str(row["full_name"]),
                default_branch=row["default_branch"],
                is_allowed=bool(row["is_allowed"]),
            )
            for row in runtime_database.list_repositories()
        ]

    @app.get("/api/v1/scans", response_model=list[ScanResponse], dependencies=[auth])
    def scans(limit: int = Query(20, ge=1, le=100)) -> list[ScanResponse]:
        return [_row_to_scan(row) for row in runtime_database.history(limit)]

    @app.get("/api/v1/scans/{scan_id}/report", dependencies=[auth])
    def scan_report(scan_id: str) -> dict[str, object]:
        if runtime_database.scan(scan_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return build_report(runtime_database, scan_id, github=None)

    return app


@lru_cache(maxsize=1)
def get_app() -> FastAPI:
    return create_app()
