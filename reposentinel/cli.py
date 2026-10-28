from __future__ import annotations

from pathlib import Path
import json

import typer
from rich.console import Console
from rich.table import Table

from reposentinel import __version__
from reposentinel.allowlist import RepositoryAllowlist
from reposentinel.config import get_settings
from reposentinel.db import Database
from reposentinel.github import GitHubClient, GitHubError, MissingCredentialsError
from reposentinel.llm import OllamaClient, OllamaUnavailable, read_source_file
from reposentinel.report import build_report
from reposentinel.proposal import ProposalError, ProposalEligibilityError, propose_finding
from reposentinel.scanner import scan_repository

app = typer.Typer(help="Local-first GitHub repository security and maintenance agent.")
console = Console()


def _database() -> tuple[Database, object]:
    settings = get_settings()
    database = Database(settings.database_path)
    database.initialize()
    return database, settings


@app.callback()
def main() -> None:
    """RepoSentinel AI - Detect. Repair. Validate. Review."""


@app.command()
def status() -> None:
    """Show configuration and persistence status without revealing credentials."""
    database, settings = _database()
    repositories = database.list_repositories()
    selected = sum(1 for row in repositories if bool(row["is_allowed"]))
    console.print(f"RepoSentinel AI {__version__}")
    console.print(f"Database: {settings.database_path}")
    console.print(f"GitHub token: {'configured' if settings.github_token else 'missing'}")
    console.print(f"Selected repositories: {selected}")
    console.print(f"Persisted repositories: {len(repositories)}")
    console.print(f"Schedule: {settings.schedule_start}-{settings.schedule_end} ({settings.timezone})")


@app.command("repos")
def repos() -> None:
    """List accessible GitHub repositories and their local selection state."""
    database, settings = _database()
    if settings.github_token:
        try:
            for remote in GitHubClient(settings).list_repositories():
                database.upsert_repository(remote.full_name, default_branch=remote.default_branch, description=remote.description)
        except GitHubError as error:
            console.print(f"[yellow]GitHub repository listing unavailable:[/yellow] {error}")
    rows = database.list_repositories()
    table = Table("Repository", "Selected", "Default branch")
    for row in rows:
        table.add_row(str(row["full_name"]), "yes" if bool(row["is_allowed"]) else "no", str(row["default_branch"] or "-"))
    console.print(table if rows else "No accessible repositories recorded. Configure a token and run repos again.")


@app.command()
def select(repository: str, remove: bool = typer.Option(False, "--remove", help="Remove the repository from the local selection.")) -> None:
    """Select or deselect one accessible repository; selection never grants other repositories access."""
    database, settings = _database()
    try:
        client = GitHubClient(settings)
        remote = next((item for item in client.list_repositories() if item.full_name == repository.strip().lower()), None)
        if remote is None:
            console.print(f"[red]Repository is not accessible to the configured token:[/red] {repository}")
            raise typer.Exit(code=2)
        database.upsert_repository(remote.full_name, default_branch=remote.default_branch, description=remote.description)
        database.set_repository_selection(remote.full_name, not remove)
    except (MissingCredentialsError, GitHubError) as error:
        console.print(f"[red]Selection unavailable:[/red] {error}")
        raise typer.Exit(code=2) from error
    console.print(f"{'Deselected' if remove else 'Selected'} {remote.full_name}")


@app.command()
def history(limit: int = typer.Option(20, min=1, max=100, help="Maximum scans to show.")) -> None:
    """Show persisted scan history, commit identities, findings status and errors."""
    database, _ = _database()
    table = Table("Started", "Repository", "Status", "Commit", "Eligible", "Selected", "Analyzed", "Failed", "Skipped", "Summary", "Error")
    rows = database.history(limit)
    for row in rows:
        table.add_row(str(row["started_at"]), str(row["full_name"]), str(row["status"]), str(row["commit_sha"] or "-")[:12], str(row["files_eligible"]), str(row["files_selected"]), str(row["files_scanned"]), str(row["files_failed"]), str(row["files_skipped"]), str(row["summary"] or "-"), str(row["error"] or "-"))
    console.print(table if rows else "No scan history yet.")


def _report_for_cli(database: Database, settings: object, scan_id: str | None) -> dict[str, object]:
    github = None
    if getattr(settings, "github_token", None):
        try:
            github = GitHubClient(settings)  # type: ignore[arg-type]
        except MissingCredentialsError:
            github = None
    return build_report(database, scan_id, github=github)


@app.command()
def findings(scan_id: str | None = typer.Option(None, "--scan-id", help="Persisted scan ID; defaults to the latest scan.")) -> None:
    """Show findings and independently verified citations from a persisted scan."""
    database, settings = _database()
    try:
        report = _report_for_cli(database, settings, scan_id)
    except ValueError as error:
        console.print(f"[yellow]{error}[/yellow]")
        raise typer.Exit(code=2) from error
    scan = report["scan"]
    console.print(
        f"{report['repository']} @ {report['commit_sha']} "
        f"({scan['status']}) | eligible {scan['eligible']}, selected {scan['selected']}, "
        f"analyzed {scan['analyzed']}, failed {scan['failed']}, skipped {scan['skipped']}"
    )
    rows = report["findings"]
    if not rows:
        console.print("No findings recorded for this scan.")
        if scan["status"] != "complete":
            console.print("[yellow]The scan was incomplete; absence of findings is not a security conclusion.[/yellow]")
        for limitation in report["limitations"]:
            console.print(f"[dim]Limitation: {limitation}[/dim]")
        return
    table = Table("Severity", "Confidence", "File:lines", "Verification", "Title", "Evidence", "Next steps")
    for finding in rows:  # type: ignore[union-attr]
        table.add_row(
            str(finding["severity"]), str(finding["confidence"]),
            f"{finding['file']}:{finding['line_start']}-{finding['line_end']}",
            str(finding["verification_status"]), str(finding["title"]),
            str(finding["evidence"]), " ".join(str(step) for step in finding["next_steps"]),
        )
    console.print(table)
    for finding in rows:  # type: ignore[union-attr]
        console.print(f"\n{finding['title']}: {finding['explanation']}")
        console.print(f"Verification: {finding['verification_reason'] or 'not verified'}")


@app.command()
def export(
    output: Path = typer.Argument(Path("sentraforge-report.json"), help="Destination JSON report path."),
    scan_id: str | None = typer.Option(None, "--scan-id", help="Persisted scan ID; defaults to the latest scan."),
) -> None:
    """Export a persisted scan report without source dumps, credentials, or secrets."""
    database, settings = _database()
    try:
        report = _report_for_cli(database, settings, scan_id)
    except ValueError as error:
        console.print(f"[yellow]{error}[/yellow]")
        raise typer.Exit(code=2) from error
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    console.print(f"Exported {report['repository']} scan report to {output}")


@app.command()
def propose(finding_id: str = typer.Option(..., "--finding-id", help="Persisted supported finding ID.")) -> None:
    """Generate and validate a read-only patch proposal for one supported finding."""
    database, settings = _database()
    try:
        result = propose_finding(
            finding_id,
            settings=settings,
            database=database,
            github=GitHubClient(settings),
            ollama=OllamaClient(settings),
        )
    except (MissingCredentialsError, GitHubError, OllamaUnavailable, ProposalError, ValueError) as error:
        console.print(f"[red]Proposal refused:[/red] {error}")
        raise typer.Exit(code=2) from error
    console.print_json(data={
        "proposal_id": result.proposal_id,
        "finding_id": result.finding_id,
        "status": result.status,
        "target_file": result.target_file,
        "base_commit_sha": result.base_commit_sha,
        "validation_errors": result.errors,
        "read_only": True,
    })


@app.command()
def proposals(limit: int = typer.Option(50, min=1, max=200, help="Maximum proposals to show.")) -> None:
    """List stored read-only patch proposals and their validation state."""
    database, _ = _database()
    rows = database.proposals(limit)
    table = Table("Created", "Proposal", "Repository", "Finding", "Target", "Base commit", "Status", "Errors")
    for row in rows:
        table.add_row(str(row["created_at"]), str(row["id"]), str(row["full_name"]), str(row["finding_id"]), str(row["target_file"]), str(row["base_commit_sha"])[:12], str(row["validation_status"]), str(row["validation_errors"] or "-"))
    console.print(table if rows else "No patch proposals recorded.")


@app.command("proposal")
def proposal_detail(proposal_id: str) -> None:
    """Display one stored proposal, including its untrusted diff and validation notes."""
    database, _ = _database()
    row = database.proposal(proposal_id)
    if row is None:
        console.print(f"[yellow]Proposal not found:[/yellow] {proposal_id}")
        raise typer.Exit(code=2)
    console.print_json(data={
        "proposal_id": row["id"],
        "finding_id": row["finding_id"],
        "repository": row["full_name"],
        "target_file": row["target_file"],
        "base_commit_sha": row["base_commit_sha"],
        "model": row["model_name"],
        "created_at": row["created_at"],
        "status": row["validation_status"],
        "validation_errors": row["validation_errors"],
        "rationale": row["rationale"],
        "expected_behavior_change": row["expected_behavior_change"],
        "risks": json.loads(row["risks_json"] or "[]"),
        "validation_recommendations": json.loads(row["validation_recommendations_json"] or "[]"),
        "proposed_diff": row["proposed_diff"],
        "read_only": True,
    })


@app.command()
def scan(repository: str) -> None:
    """Read and analyze selected source files from an allowlisted GitHub repository."""
    database, settings = _database()
    try:
        result = scan_repository(repository, settings=settings, database=database, github=GitHubClient(settings), ollama=OllamaClient(settings))
    except (MissingCredentialsError, GitHubError, PermissionError, ValueError) as error:
        console.print(f"[red]Scan unavailable:[/red] {error}")
        raise typer.Exit(code=2) from error
    console.print_json(data={
        "repository": result.repository,
        "status": result.status,
        "commit_sha": result.commit_sha,
        "files_scanned": result.files_scanned,
        "files_eligible": result.files_eligible,
        "files_selected": result.files_selected,
        "files_failed": result.files_failed,
        "files_skipped": result.files_skipped,
        "source_bytes": result.source_bytes,
        "findings": result.findings,
        "summary": result.summary,
        "errors": result.errors,
    })


@app.command()
def analyze(
    file: Path = typer.Argument(..., exists=True, readable=True, help="Local source file to analyze."),
    repository: str | None = typer.Option(None, help="Explicit allowlisted repository name for this file."),
    repository_root: Path | None = typer.Option(None, help="Root containing the selected repository file."),
) -> None:
    """Analyze one local source file with the configured local Ollama model."""
    settings = get_settings()
    if repository is not None:
        RepositoryAllowlist.from_values(settings.allowed_repositories).require(repository)
    root = (repository_root or file.parent).resolve()
    try:
        source, relative_path = read_source_file(file, root=root, max_bytes=settings.analysis_max_source_bytes)
        client = OllamaClient(settings)
        if not client.check_connectivity():
            raise OllamaUnavailable(f"Ollama is unavailable at {settings.ollama_endpoint}")
        assessment = client.analyze(source=source, relative_path=relative_path)
    except (OllamaUnavailable, ValueError, FileNotFoundError, PermissionError) as error:
        console.print(f"[red]Analysis unavailable:[/red] {error}")
        raise typer.Exit(code=2) from error
    console.print_json(data=assessment.model_dump(mode="json"))


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address; keep loopback for local use."),
    port: int = typer.Option(8000, min=1, max=65535, help="HTTP port."),
) -> None:
    """Serve the authenticated, read-only scan API for local dashboard development."""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        console.print("[red]Refusing non-loopback bind; production user/session authorization is not implemented.[/red]")
        raise typer.Exit(code=2)
    import uvicorn

    uvicorn.run("reposentinel.auth_api:get_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    app()
