# RepoSentinel AI

RepoSentinel AI is a local-first GitHub repository security and maintenance agent.

Tagline: **Detect. Repair. Validate. Review.**

## Current status

The read-only repository workflow is implemented: GitHub REST pagination, explicit local selection, commit-pinned source retrieval, bounded Ollama analysis, evidence validation, SQLite scan history, and incomplete-scan reporting.

## Installation

Use Python 3.13.5 on Windows. From the project directory:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
Copy-Item .env.example .env
```

Keep `.env` local and untracked. Create a GitHub fine-grained token with only `Contents: Read-only` and `Metadata: Read-only` for the repositories you intend to inspect. Set it as `REPOSENTINEL_GITHUB_TOKEN`; it is never printed or logged. The persisted SQLite selection starts empty and denies every repository until you explicitly select one.

## Repository selection and scanning

```powershell
.\.venv\Scripts\python.exe -m reposentinel repos
.\.venv\Scripts\python.exe -m reposentinel select OWNER/REPO
.\.venv\Scripts\python.exe -m reposentinel scan OWNER/REPO
.\.venv\Scripts\python.exe -m reposentinel history
.\.venv\Scripts\python.exe -m reposentinel findings
.\.venv\Scripts\python.exe -m reposentinel export report.json
.\.venv\Scripts\python.exe -m reposentinel propose --finding-id FINDING_ID
.\.venv\Scripts\python.exe -m reposentinel proposals
.\.venv\Scripts\python.exe -m reposentinel proposal PROPOSAL_ID
```

For local dashboard/API development, run the authenticated API on loopback:

```powershell
.\.venv\Scripts\python.exe -m reposentinel serve
```

The API binds to loopback only, provides email/password registration and expiring bearer sessions, and is read-only. It exposes authenticated repository metadata, scan summaries, and credential-free JSON reports under `/api/v1/`. GitHub App installation requires `REPOSENTINEL_GITHUB_APP_SLUG` and `REPOSENTINEL_GITHUB_APP_STATE_KEY`; installation token acquisition remains an injected integration boundary. This is not production-ready multi-user deployment: do not expose it remotely until deployment-grade identity verification, CSRF protection, rate limiting, GitHub App credential handling, and encrypted secret storage are implemented.

`repos` refreshes accessible repositories when a token is configured and shows the persisted `Selected` state. `select` verifies that the repository is accessible before enabling it. Use `select OWNER/REPO --remove` to revoke selection. `scan` only reads repository metadata, the default-branch tree, and supported UTF-8 source files through the GitHub API; it never clones, executes, installs, writes, pushes, or opens pull requests.

The default scan limit is 100 source files, 100,000 bytes per file, and 2,000,000 total source bytes. Configure `REPOSENTINEL_SCAN_MAX_FILES`, `REPOSENTINEL_SCAN_MAX_FILE_BYTES`, `REPOSENTINEL_SCAN_MAX_SOURCE_BYTES`, and `REPOSENTINEL_SUPPORTED_SOURCE_EXTENSIONS` for a smaller or larger bounded scope. Truncated trees, skipped files, API failures, unavailable Ollama, and malformed model assessments are recorded as incomplete; a clean model response is not a claim that the repository is secure. Scan history distinguishes eligible, selected, analyzed, failed, and skipped files.

`findings` displays the latest persisted findings (use `--scan-id ID` for a specific run), including severity, model confidence, exact file/line citation, evidence, explanation, verification status, and next steps. Verification is independent of the model: `supported` means only that the citation matches the pinned commit; `rejected` means it does not; `unverified` means the pinned source could not be checked. None of these statuses proves that a vulnerability exists.

`export report.json` writes a JSON report containing the repository, pinned commit, coverage metrics, per-file outcomes, findings, verification state, errors, and limitations. It never includes credentials or raw source dumps. Exporting a report may make read-only GitHub content requests to recheck citations at the scan commit when a token is configured.

## Read-only repair proposals

`propose --finding-id FINDING_ID` is available only for a finding whose evidence was independently marked `supported`. It retrieves the exact source at the finding's scan commit, asks the local Ollama model for one structured minimal unified diff, validates the target path, hunk structure, line counts, and applicability, and stores the result in SQLite. Configure `REPOSENTINEL_PROPOSAL_MAX_DIFF_BYTES` to bound the diff size.

Use `proposals` to list stored results and `proposal PROPOSAL_ID` to display a proposal. Results are labeled `proposed` when the diff is structurally valid and applicable, or `invalid` when generation/validation failed. A proposal is untrusted and still requires human review; it is not proof that a vulnerability is fixed. `unverified` and `rejected` findings are refused without changing their verification status. This milestone never applies diffs, writes repository files, creates branches, commits, pushes, opens pull requests, executes repository code, or installs dependencies.

## Local LLM analysis

Install [Ollama](https://ollama.com), start it, and pull a local model, for example:

```powershell
ollama pull qwen2.5-coder:3b
```

Configure `REPOSENTINEL_OLLAMA_ENDPOINT` and `REPOSENTINEL_OLLAMA_MODEL` if needed. Analyze a local file in read-only mode:

```powershell
.\.venv\Scripts\python.exe -m reposentinel analyze .\src\app.py
```

For an explicitly selected repository root, include its allowlisted name and root:

```powershell
.\.venv\Scripts\python.exe -m reposentinel analyze .\checkout\app.py --repository acme/widget --repository-root .\checkout
```

The command fails clearly if Ollama is unavailable, the repository is not allowlisted, the file escapes the selected root, or the model returns invalid/unverifiable evidence. Source content is sent only to the configured local endpoint by default. The model never executes tools or shell commands, and model output cannot bypass policy checks.

Ollama requests use the Pydantic assessment JSON Schema through Ollama's structured-output `format` support. Each request contains one line-numbered representation of the exact pinned source file; findings must copy evidence from the cited lines and use that file's path. Responses are still parsed and validated locally, including strict rejection of unknown fields, empty/non-object responses, invalid line ranges, and evidence not present in the cited lines. A bounded corrective retry may include only a short validation error; exhausted or failed file assessments are recorded as incomplete and never reclassified as clean.

Findings must also provide a plausible attack path, affected security property, attacker prerequisites, and concrete impact. A raw return value or generic statement that data "could leak" is not sufficient without a source-grounded downstream sink or authorization/data-flow impact. A clean assessment with no findings is appropriate when the supplied file does not establish such an impact.

## Deterministic local demo

The test suite includes an isolated synthetic fixture at `tests/fixtures/vulnerable_password_logging.py`. It is read as text only; it is never executed. A mocked Ollama response demonstrates exact line/evidence validation for a password written to output:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_demo_fixture -v
```

For a live local-model demonstration against that fixture, use `analyze`. This requires Ollama to be running and may return `incomplete` or fail if the model cannot produce a valid source-grounded assessment:

```powershell
ollama list
.\.venv\Scripts\python.exe -m reposentinel analyze .\tests\fixtures\vulnerable_password_logging.py
```

The deterministic test is the reliable presentation check; a live model response is informative but not a substitute for evidence verification or human review.

## Usage

```powershell
.\.venv\Scripts\python.exe -m reposentinel --help
.\.venv\Scripts\python.exe -m reposentinel status
.\.venv\Scripts\python.exe -m reposentinel repos
.\.venv\Scripts\python.exe -m reposentinel history
```

The default schedule is 19:00–23:00 in `Asia/Kolkata`. A local agent cannot scan while the machine is powered off; missed-run handling will be added with the scheduler.

## Security boundaries

The project does not execute repository code, install repository dependencies, create branches, write repository files, push, or open pull requests. Future repair actions must remain behind explicit approvals bound to a base commit and patch hash.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite uses mocked GitHub and Ollama responses and does not require a GitHub token or network access. It verifies schema validation, exact evidence matching, incomplete-scan persistence, report export, proposal safety, retry behavior, and the synthetic demo fixture.
## GitHub App integration (read-only foundation)

SentraForge can discover repositories through a GitHub App without cloning or executing repository code. The App must use only the minimum read permissions: repository metadata (read-only) and contents (read-only). Do not grant Actions, workflows, administration, pull request write, or organization-management permissions.

To configure a local installation, create a GitHub App at GitHub Settings → Developer settings → GitHub Apps. Under **Post installation**, set the **Setup URL** (not the OAuth callback URL) to the value of `REPOSENTINEL_GITHUB_APP_REDIRECT_URI`, normally `http://127.0.0.1:8000/api/v1/github/installations/callback`, and enable **Redirect on update**. Set the App URL to the same local service, enable the read-only repository permissions above, and install the App only on repositories you intend to inspect. GitHub sends `installation_id` to the Setup URL; SentraForge validates it against the signed state and connected GitHub identity before persistence. Download the generated private key and store its path in `REPOSENTINEL_GITHUB_APP_PRIVATE_KEY_PATH`; never commit the key or put it in logs. Set the numeric App ID, slug, and a random `REPOSENTINEL_GITHUB_APP_STATE_KEY` in `.env`.

The installation callback is user-bound and expiring. A state value is persisted and consumed once, and the production provider fails closed unless it can verify that the authenticated user is authorized for the installation. The automated tests use mocked GitHub responses; configure and verify a real App separately before relying on live discovery.

The App integration has no write permissions and this milestone does not create branches, commits, pull requests, or repairs. GitHub failures, revoked installations, expired tokens, and inaccessible repositories are reported as errors; they are never interpreted as an empty or universally authorized repository list. Existing per-user selection records remain isolated by local user ID and stable GitHub repository ID.

### GitHub user identity connection

Before installing the App, the future frontend must call `GET /api/v1/github/oauth/start` with the SentraForge bearer session. The backend returns an authorization URL containing a signed, user-bound, one-time state. GitHub redirects to `GET /api/v1/github/oauth/callback?code=...&state=...`; this callback intentionally does not require a SentraForge bearer header. The backend consumes the state, exchanges the code, calls GitHub `/user`, and stores the stable GitHub user ID plus display login. It then encrypts the OAuth token at rest with AES-GCM.

The frontend must retain the local session for the installation flow: call `GET /api/v1/github/installations/start` with the bearer token, send the user to the returned App installation URL, then allow GitHub to redirect to the callback. The installation callback derives the local user from the signed state and does not trust the browser-supplied installation ID as authorization. It verifies the stored GitHub identity through the server-side token resolver before persisting repositories.

For repository discovery, configure the GitHub App user-authorization credentials: `REPOSENTINEL_GITHUB_APP_CLIENT_ID`, `REPOSENTINEL_GITHUB_APP_CLIENT_CREDENTIAL`, and `REPOSENTINEL_GITHUB_APP_OAUTH_REDIRECT_URI` (normally `http://127.0.0.1:8000/api/v1/github/oauth/callback`). These are the App's OAuth client ID and generated client secret, not the numeric App ID, private key, or a separate OAuth App credential. SentraForge then stores a GitHub App user access token, which GitHub requires for `GET /user/installations`. The legacy `REPOSENTINEL_GITHUB_OAUTH_CLIENT_ID` and `REPOSENTINEL_GITHUB_OAUTH_CLIENT_CREDENTIAL` fields remain supported for identity-only OAuth use, but their token cannot discover GitHub App installations. Also configure a random base64-encoded 16/24/32-byte `REPOSENTINEL_GITHUB_TOKEN_ENCRYPTION_KEY`. Do not put credentials or encryption keys in source control or chat. A resolver with no stored identity, corrupt ciphertext, or a revoked GitHub token fails closed.
# Next.js dashboard

The first dashboard milestone lives in [`frontend/`](./frontend/). It is a separate Next.js App Router application and does not replace the Python CLI or scanner.

From PowerShell:

```powershell
cd frontend
Copy-Item .env.example .env.local
npm install
npm run dev
```

Run the backend separately, for example `python -m reposentinel serve`, then open `http://localhost:3000`. The development proxy sends `/backend/*` requests to `BACKEND_API_URL` (default `http://127.0.0.1:8000`). The browser only receives the local SentraForge bearer session; GitHub OAuth tokens, App private keys, and encryption keys remain backend-only. Because the current backend contract uses bearer sessions, the dashboard keeps that session in `sessionStorage` rather than `localStorage`; this is still readable by JavaScript and should be replaced by an HttpOnly same-origin cookie/BFF before production deployment.

The dashboard uses only persisted API data: `/api/v1/repositories`, `/api/v1/repositories/sync`, `/api/v1/repositories/{github_repo_id}/selection`, `/api/v1/scans`, `/api/v1/scans/{scan_id}/report`, and `/api/v1/github/identity`. Use the protected `POST /api/v1/repositories/sync` action after the GitHub App callback to refresh every installation already associated with the authenticated local user. The browser never supplies an installation ID for synchronization. It does not fabricate findings or security scores. Connect GitHub starts the backend's signed, one-time OAuth flow. Configure the backend OAuth redirect URI as `http://localhost:3000/github/callback` for the dashboard callback page, and configure the GitHub App installation callback according to the backend setup instructions. The installation action remains unavailable until the App is configured.

Frontend checks:

```powershell
npm run typecheck
npm run lint
npm run build
```

The dashboard is local-development ready. Real GitHub discovery and scans still require valid backend GitHub OAuth/App credentials, an encryption key, Ollama, and an explicitly authorized installation. Scheduling, repair proposals, pull requests, cloud deployment, and production-grade cookie/BFF authentication are not part of this milestone.
