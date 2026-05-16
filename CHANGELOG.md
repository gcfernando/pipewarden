# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-05-17

### Added

- **24 new secret patterns** — 46 total (up from 22 in 1.1.0), organised into 9 categories:
  - **Database URIs** — `postgres.connection_string`, `mysql.connection_string`, `redis.connection_string`, `amqp.connection_string`
  - **SQL / JDBC** — `mssql.connection_string` (SQL Server ADO.NET key=value format with negative lookahead to skip Windows Integrated Security), `jdbc.connection_string` (JDBC URL `password=` parameter)
  - **Azure** — `azure.storage_connection_string` (`DefaultEndpointsProtocol=…;AccountKey=…`), `azure.cosmos_connection_string` (`AccountEndpoint=…;AccountKey=…`), `azure.servicebus_connection_string` (`Endpoint=sb://…;SharedAccessKey=…`)
  - **AWS** — `aws.sts_key` (STS/AssumeRole temporary credentials, `ASIA` prefix)
  - **Developer platforms** — `digitalocean.token` (`dop_v1_`), `github.actions_token` (`ghs_`), `github.user_token` (`ghu_`), `linear.api_key` (`lin_api_`), `okta.token` (`SSWS `)
  - **AI / ML** — `huggingface.token` (`hf_`), `replicate.token` (`r8_`)
  - **Communication** — `telegram.bot_token` (`numeric_id:AA…`)
  - **Payment** — `stripe.test_key` (`sk_test_`), `stripe.webhook_secret` (`whsec_`)
  - **E-commerce** — `shopify.access_token` (`shpat_`), `shopify.storefront_token` (`shpss_`), `shopify.custom_app_token` (`shpca_`)
  - **Observability** — `newrelic.license_key` (`NRAK-`)

### Fixed

- **Self-scan false positive** — `.pipewarden.toml` is now always excluded from secret scanning via `allowlist_paths`; the config file's own `allowlist_strings` entries can match secret patterns, causing a loop
- **README documentation examples** — connection string examples in docs are now written in split form (e.g. `` `mongodb://HOST/DB` ``) so the scanner's `[^:@\s]` stop-at-whitespace rule cannot match across a documentation line

### Changed

- Test suite expanded from 73 to **160 tests** (+87); coverage ≥ 85 %

## [1.1.0] — 2026-05-17

### Added

- **22 secret patterns** (up from 12): GitLab PAT (`glpat-`), Twilio Account SID, SendGrid API key, Anthropic API key, OpenAI classic and project-format keys, Databricks personal token (`dapi`), HashiCorp Vault service token (`hvs.`), MongoDB connection string, PyPI API token
- **`**` glob support** in `allowlist_paths` — patterns like `tests/fixtures/**` now work correctly; previously `fnmatch` silently ignored `**`
- **`[retry]` config section** (`attempts`, `backoff_base`) — retries network-heavy steps (pip install, npm ci, cargo fetch, go mod download, etc.) on transient failures with exponential backoff
- **`PIPEWARDEN_*` environment variable overrides** — all major settings can be set via env vars (FAIL_FAST, SKIP, ONLY, TIMEOUT_*, NO_COLOR, QUIET, RETRY_ATTEMPTS, RETRY_BACKOFF); priority: CLI > env vars > TOML > defaults
- **`EXIT_SECRETS = 4`** — secrets scan failure now returns exit code 4 instead of 1, allowing CI scripts to distinguish "credential leak" from "test failure"
- **`--dry-run` flag** — prints which stages would run without executing anything
- **`--init` flag** — scaffolds a `.pipewarden.toml` with commented-out defaults
- **`--validate` flag** — validates the config file and exits (0 = valid, 3 = error)
- **`--list-stages` flag** — shows which stages are detected and enabled for the current project
- **`--markdown-out PATH` flag** — writes a Markdown summary table; pipe to `$GITHUB_STEP_SUMMARY` for GitHub Actions step panels
- **`--gh-annotations` flag** — prints GitHub Actions `::error file=...` annotations to stdout for inline PR diff comments
- **SARIF fingerprints** — each finding now includes a SHA-256 fingerprint (`primaryLocationLineHash/v1`) for GitHub Code Scanning deduplication; the same secret detected across multiple runs is no longer reported as a new alert each time
- **`to_github_annotations()`** in `reporters.py` — new report serializer
- **`to_markdown_summary()`** in `reporters.py` — new report serializer (truncates at 100 findings with a note to use `--sarif-out` for the full list)
- **Docker daemon availability check** — `run_docker()` now runs `docker info` before attempting `docker build`; emits `WARNED` (not `FAILED`) when the daemon is absent in a detected CI environment (CI / GITHUB_ACTIONS / GITLAB_CI / TF_BUILD)

### Fixed

- JUnit failure type was `PipelineGuardFailure` — corrected to `PipewarnedFailure`

## [1.0.0] — 2026-05-16

### Added
- Project detection for Python (pip/poetry/uv), Node (npm/pnpm/yarn), .NET, Go, Rust, Docker
- Secret scanning with `gitleaks` if installed, regex fallback otherwise
- Allowlists by path, rule, and string for the fallback scanner
- Dependency vulnerability scanning via `pip-audit`, `npm audit`, `cargo-audit`, `govulncheck`
- SARIF 2.1 and JUnit XML report writers
- TOML config file (`.pipewarden.toml`) with strict schema validation
- Stable CLI exit codes (0/1/2/3/130)
- `--version`, `--json`, `--only`, `--skip`, `--fail-fast`, `--log-file`, `--no-color`
- Subprocess timeouts on every command
- `python -m pipewarden` entry point
- 50+ tests; CI matrix across Linux/macOS/Windows and Python 3.10–3.13
- Signed releases via Sigstore (PyPI Trusted Publisher)
