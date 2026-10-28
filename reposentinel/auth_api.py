from __future__ import annotations

from functools import lru_cache
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Protocol
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, HTTPException, Query, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from reposentinel.auth import hash_password, new_session_token, normalize_email, session_expiry, verify_password
from reposentinel.config import Settings, get_settings
from reposentinel.db import Database
from reposentinel.github_app import InstallationRepository, InstallationInfo, installation_state_nonce, installation_state_user_id, issue_installation_state, verify_installation_state
from reposentinel.github_app import GitHubAppClient, GitHubAppError
from reposentinel.github_oauth import GitHubIdentity, GitHubOAuthError, GitHubOAuthClient, GitHubTokenStore, TokenCipher, oauth_state, oauth_state_nonce, verify_oauth_state
from reposentinel.report import build_report

logger = logging.getLogger(__name__)


def _sync_error(error: GitHubAppError, *, stage: str) -> HTTPException:
    status_code = error.status_code or 502
    logger.warning("github repository sync failed stage=%s code=%s status=%s", stage, error.code, status_code)
    return HTTPException(status_code=status_code, detail={"code": error.code, "message": str(error)})


class InstallationProvider(Protocol):
    def get_installation(self, installation_id: int) -> InstallationInfo: ...
    def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]: ...
    def list_user_installations(self, user_id: str) -> list[int]: ...

    def is_user_authorized(self, installation_id: int, user_id: str) -> bool: ...


class OAuthProvider(Protocol):
    def authorization_url(self, state: str) -> str: ...
    def exchange_code(self, code: str) -> str: ...
    def authenticated_identity(self, token: str) -> GitHubIdentity: ...


class AuthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=256)


class AuthResponse(BaseModel):
    user_id: str
    email: str
    access_token: str
    token_type: str = "bearer"


class SelectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selected: bool


class RepositoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    github_repo_id: int
    installation_id: str
    full_name: str
    default_branch: str | None
    description: str | None
    private: bool
    selected: bool


class RepositorySyncResponse(BaseModel):
    installations_synchronized: int
    repositories_synchronized: int


bearer = HTTPBearer(auto_error=False)


def _repository_response(row: Any) -> RepositoryResponse:
    return RepositoryResponse(
        github_repo_id=int(row["github_repo_id"]), installation_id=str(row["installation_id"]),
        full_name=str(row["full_name"]), default_branch=row["default_branch"],
        description=row["description"], private=bool(row["private"]), selected=bool(row["selected"]),
    )


def create_app(*, settings: Settings | None = None, database: Database | None = None,
               github_app: InstallationProvider | None = None,
               github_oauth: OAuthProvider | None = None) -> FastAPI:
    """Create the multi-user, read-only GitHub App foundation.

    Installation token acquisition is deliberately injected. This prevents the API from
    accepting a GitHub token from a browser and keeps live App credentials outside tests.
    """
    runtime_settings = settings or get_settings()
    runtime_database = database or Database(runtime_settings.database_path)
    runtime_database.initialize()
    token_store: GitHubTokenStore | None = None
    if runtime_settings.github_token_encryption_key:
        token_store = GitHubTokenStore(runtime_database, TokenCipher(runtime_settings.github_token_encryption_key.get_secret_value()))
        token_store.ensure_schema()
    if github_oauth is None and runtime_settings.github_oauth_client_id and runtime_settings.github_oauth_client_credential:
        github_oauth = GitHubOAuthClient(runtime_settings)
    if github_app is None and runtime_settings.github_app_id and token_store is not None:
        github_app = GitHubAppClient(runtime_settings, user_token_resolver=token_store.get_token)
    app = FastAPI(title="SentraForge AI authenticated API", version="0.1.0")

    def current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)]) -> Any:
        if not credentials:
            raise HTTPException(status_code=401, detail="Authentication required")
        token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        user = runtime_database.user_by_session_hash(token_hash)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return user

    user_dependency = Depends(current_user)

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "read_only": True, "multi_user_auth": True}

    @app.post("/api/v1/auth/register", response_model=AuthResponse, status_code=201)
    def register(request: AuthRequest) -> AuthResponse:
        email = normalize_email(str(request.email))
        try:
            user_id = runtime_database.create_user(email, hash_password(request.password))
        except Exception as error:
            if "UNIQUE constraint failed: users.email" not in str(error):
                raise
            raise HTTPException(status_code=409, detail="An account with that email already exists") from error
        token, token_hash = new_session_token()
        runtime_database.create_session(user_id, token_hash, session_expiry())
        return AuthResponse(user_id=user_id, email=email, access_token=token)

    @app.post("/api/v1/auth/login", response_model=AuthResponse)
    def login(request: AuthRequest) -> AuthResponse:
        email = normalize_email(str(request.email))
        user = runtime_database.user_by_email(email)
        if user is None or not verify_password(request.password, str(user["password_hash"])):
            raise HTTPException(status_code=401, detail="Invalid email or password")
        token, token_hash = new_session_token()
        runtime_database.create_session(str(user["id"]), token_hash, session_expiry())
        return AuthResponse(user_id=str(user["id"]), email=email, access_token=token)

    @app.post("/api/v1/auth/logout", status_code=204)
    def logout(credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)]) -> None:
        if credentials:
            runtime_database.revoke_session(hashlib.sha256(credentials.credentials.encode()).hexdigest())

    @app.get("/api/v1/github/installations/start", dependencies=[user_dependency])
    def installation_start(user: Any = user_dependency) -> dict[str, str]:
        if not runtime_settings.github_app_slug or not runtime_settings.github_app_state_key:
            raise HTTPException(status_code=503, detail="GitHub App installation is not configured")
        state = issue_installation_state(str(user["id"]), runtime_settings.github_app_state_key.get_secret_value())
        try:
            runtime_database.store_installation_state(
                installation_state_nonce(state),
                str(user["id"]),
                (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            )
        except Exception as error:
            raise HTTPException(status_code=503, detail="Could not prepare GitHub installation state") from error
        query = {"state": state}
        if runtime_settings.github_app_redirect_uri:
            query["redirect_uri"] = runtime_settings.github_app_redirect_uri
        return {"install_url": f"https://github.com/apps/{runtime_settings.github_app_slug}/installations/new?{urlencode(query)}"}

    @app.get("/api/v1/github/oauth/start", dependencies=[user_dependency])
    def github_oauth_start(user: Any = user_dependency) -> dict[str, str]:
        if github_oauth is None or token_store is None or not runtime_settings.github_app_state_key:
            raise HTTPException(status_code=503, detail="GitHub OAuth is not configured")
        state = oauth_state(str(user["id"]), runtime_settings.github_app_state_key.get_secret_value())
        try:
            token_store.store_state(oauth_state_nonce(state), str(user["id"]), (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat())
            return {"authorize_url": github_oauth.authorization_url(state)}
        except Exception as error:
            raise HTTPException(status_code=503, detail="Could not prepare GitHub OAuth state") from error

    @app.get("/api/v1/github/identity", dependencies=[user_dependency])
    def github_identity_status(user: Any = user_dependency) -> dict[str, object]:
        """Expose connection metadata only; never return the stored OAuth token."""
        if token_store is None:
            return {"connected": False, "github_user_id": None, "github_login": None}
        identity = token_store.get_identity(str(user["id"]))
        if identity is None:
            return {"connected": False, "github_user_id": None, "github_login": None}
        return {
            "connected": True,
            "github_user_id": identity.github_user_id,
            "github_login": identity.login,
        }

    @app.get("/api/v1/github/oauth/callback")
    def github_oauth_callback(state: str, code: str | None = None, error: str | None = None) -> dict[str, object]:
        secret = runtime_settings.github_app_state_key
        if not secret or not verify_oauth_state(state, secret.get_secret_value()):
            raise HTTPException(status_code=400, detail="Invalid or expired GitHub OAuth state")
        if github_oauth is None or token_store is None:
            raise HTTPException(status_code=503, detail="GitHub OAuth is not configured")
        try:
            owner = token_store.consume_state(oauth_state_nonce(state))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid or already-used GitHub OAuth state") from exc
        if owner is None:
            raise HTTPException(status_code=400, detail="Invalid or already-used GitHub OAuth state")
        if error or not code:
            raise HTTPException(status_code=400, detail="GitHub OAuth authorization was not completed")
        try:
            token = github_oauth.exchange_code(code)
        except GitHubOAuthError as exc:
            logger.warning("github oauth failed stage=code_exchange code=%s", exc.code)
            raise HTTPException(status_code=502, detail={"code": exc.code, "message": "GitHub OAuth could not be completed"}) from exc
        try:
            identity = github_oauth.authenticated_identity(token)
        except GitHubOAuthError as exc:
            logger.warning("github oauth failed stage=user_lookup code=%s", exc.code)
            raise HTTPException(status_code=502, detail={"code": exc.code, "message": "GitHub OAuth could not be completed"}) from exc
        try:
            token_store.save(owner, identity, token)
        except GitHubOAuthError as exc:
            logger.warning("github oauth failed stage=identity_persistence code=%s", exc.code)
            raise HTTPException(status_code=502, detail={"code": exc.code, "message": "GitHub OAuth could not be completed"}) from exc
        return {"connected": True, "github_user_id": identity.github_user_id, "github_login": identity.login}

    @app.get("/api/v1/github/installations/callback")
    @app.post("/api/v1/github/installations/callback")
    def installation_callback(state: str, installation_id: int, setup_action: str | None = None) -> dict[str, int]:
        secret = runtime_settings.github_app_state_key
        local_user_id = installation_state_user_id(state, secret.get_secret_value(), None) if secret else None
        if not local_user_id:
            raise HTTPException(status_code=400, detail="Invalid or expired installation state")
        try:
            nonce = installation_state_nonce(state)
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Invalid or expired installation state") from error
        if not runtime_database.consume_installation_state(nonce, local_user_id):
            raise HTTPException(status_code=400, detail="Invalid or already-used installation state")
        if github_app is None:
            raise HTTPException(status_code=503, detail={"code": "GITHUB_APP_NOT_CONFIGURED", "message": "GitHub App provider is not configured"})
        authorization_check = getattr(github_app, "is_user_authorized", None)
        if not callable(authorization_check) or not authorization_check(installation_id, local_user_id):
            raise HTTPException(status_code=403, detail="GitHub installation is not authorized for this user")
        try:
            installation = github_app.get_installation(installation_id)
            repositories = github_app.list_installation_repositories(installation_id)
            persisted_id = runtime_database.upsert_github_installation(
                installation.github_installation_id, installation.account_login, installation.account_type,
                permissions_json=json.dumps(installation.permissions, separators=(",", ":")),
            )
            runtime_database.link_user_installation(local_user_id, persisted_id)
            for repository in repositories:
                runtime_database.upsert_user_repository(
                    local_user_id, persisted_id, repository.github_repo_id, repository.full_name,
                    default_branch=repository.default_branch, description=repository.description, private=repository.private,
                )
        except HTTPException:
            raise
        except Exception as error:
            raise HTTPException(status_code=502, detail="GitHub App installation discovery failed") from error
        return {"installation_id": installation_id, "repositories_discovered": len(repositories)}

    @app.get("/api/v1/repositories", response_model=list[RepositoryResponse], dependencies=[user_dependency])
    def repositories(user: Any = user_dependency) -> list[RepositoryResponse]:
        return [_repository_response(row) for row in runtime_database.user_repositories(str(user["id"]))]

    @app.post("/api/v1/repositories/sync", response_model=RepositorySyncResponse, dependencies=[user_dependency])
    def sync_repositories(user: Any = user_dependency) -> RepositorySyncResponse:
        """Refresh installations already linked to the authenticated user."""
        if github_app is None:
            raise HTTPException(status_code=503, detail="GitHub App provider is not configured")
        local_user_id = str(user["id"])
        with runtime_database.connection() as connection:
            installations = list(connection.execute(
                "SELECT gi.* FROM github_installations gi JOIN user_installations ui ON ui.installation_id = gi.id WHERE ui.user_id = ? ORDER BY gi.github_installation_id",
                (local_user_id,),
            ))
        if not installations:
            discover = getattr(github_app, "list_user_installations", None)
            if callable(discover):
                try:
                    discovered_ids = discover(local_user_id)
                    for github_installation_id in discovered_ids:
                        authorization_check = getattr(github_app, "is_user_authorized", None)
                        if not callable(authorization_check) or not authorization_check(github_installation_id, local_user_id):
                            continue
                        installation = github_app.get_installation(github_installation_id)
                        persisted_id = runtime_database.upsert_github_installation(
                            installation.github_installation_id, installation.account_login,
                            installation.account_type,
                            permissions_json=json.dumps(installation.permissions, separators=(",", ":")),
                        )
                        runtime_database.link_user_installation(local_user_id, persisted_id)
                    with runtime_database.connection() as connection:
                        installations = list(connection.execute(
                            "SELECT gi.* FROM github_installations gi JOIN user_installations ui ON ui.installation_id = gi.id WHERE ui.user_id = ? ORDER BY gi.github_installation_id",
                            (local_user_id,),
                        ))
                except GitHubAppError as error:
                    raise _sync_error(error, stage="installation_discovery") from error
                except Exception as error:
                    logger.error("github repository sync failed stage=installation_persistence")
                    raise HTTPException(status_code=502, detail={"code": "INSTALLATION_PERSISTENCE_FAILED", "message": "GitHub installation could not be persisted"}) from error
        if not installations:
            error = GitHubAppError("No GitHub App installation is linked to this user", code="GITHUB_APP_NOT_INSTALLED", status_code=404)
            raise _sync_error(error, stage="installation_lookup")
        total = 0
        for installation in installations:
            github_installation_id = int(installation["github_installation_id"])
            try:
                repositories = github_app.list_installation_repositories(github_installation_id)
                with runtime_database.connection() as connection:
                    connection.execute(
                        "UPDATE user_repositories SET accessible = 0, updated_at = ? WHERE user_id = ? AND installation_id = ?",
                        (datetime.now(timezone.utc).isoformat(), local_user_id, str(installation["id"])),
                    )
                for repository in repositories:
                    runtime_database.upsert_user_repository(
                        local_user_id, str(installation["id"]), repository.github_repo_id,
                        repository.full_name, default_branch=repository.default_branch,
                        description=repository.description, private=repository.private,
                    )
                total += len(repositories)
            except GitHubAppError as error:
                raise _sync_error(error, stage="repository_discovery") from error
            except Exception as error:
                logger.error("github repository sync failed stage=repository_persistence")
                raise HTTPException(status_code=502, detail={"code": "REPOSITORY_PERSISTENCE_FAILED", "message": "Repositories were fetched but could not be persisted"}) from error
        return RepositorySyncResponse(
            installations_synchronized=len(installations),
            repositories_synchronized=total,
        )

    @app.put("/api/v1/repositories/{github_repo_id}/selection", response_model=RepositoryResponse,
             dependencies=[user_dependency])
    def select_repository(github_repo_id: int, request: SelectionRequest, user: Any = user_dependency) -> RepositoryResponse:
        try:
            runtime_database.set_user_repository_selection(str(user["id"]), github_repo_id, request.selected)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="Repository is not accessible to this user") from error
        row = next((item for item in runtime_database.user_repositories(str(user["id"]))
                    if int(item["github_repo_id"]) == github_repo_id), None)
        if row is None:
            raise HTTPException(status_code=404, detail="Repository is not accessible to this user")
        return _repository_response(row)

    @app.get("/api/v1/scans", dependencies=[user_dependency])
    def scans(limit: int = Query(20, ge=1, le=100), user: Any = user_dependency) -> list[dict[str, object]]:
        return [dict(row) for row in runtime_database.user_scan_history(str(user["id"]), limit)]

    @app.get("/api/v1/scans/{scan_id}/report", dependencies=[user_dependency])
    def scan_report(scan_id: str, user: Any = user_dependency) -> dict[str, object]:
        owned = any(str(row["id"]) == scan_id for row in runtime_database.user_scan_history(str(user["id"]), 100))
        if not owned:
            raise HTTPException(status_code=404, detail="Scan not found")
        return build_report(runtime_database, scan_id, github=None)

    return app


@lru_cache(maxsize=1)
def get_app() -> FastAPI:
    return create_app()
