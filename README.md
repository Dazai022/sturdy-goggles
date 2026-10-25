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
