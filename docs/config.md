# Reference: `.pipewarden.toml`

Drop this file at the root of your repository. All keys are optional; values shown are the built-in defaults.

Run `pipewarden --init` to scaffold this file automatically.

```toml
# Run all detected stages; collect all failures.
fail_fast = false

# Default Docker tag used by the docker stage.
docker_tag = "pipewarden-local:latest"

# Run only these stages (empty = all).
only = []

# Always skip these stages.
skip = []

[stages]
python = true
node   = true
dotnet = true
go     = true
rust   = true
docker = true
vulns  = true

[timeouts]
# Seconds. Every subprocess uses one of these.
install_s = 900
build_s   = 900
test_s    = 1800
scan_s    = 600
default_s = 600

[secrets]
enabled         = true
prefer_external = true   # use gitleaks if installed; fall back to built-in scanner
max_file_bytes  = 1_000_000
max_files       = 10_000

# Gitignore-style globs, relative to repo root. ** is fully supported.
allowlist_paths = [
    # "tests/fixtures/**",
    # "docs/examples/**",
]

# Rule IDs from the built-in scanner to skip everywhere.
allowlist_rules = [
    # "jwt",
]

# Verbatim strings to ignore wherever they appear (e.g. AWS docs example keys).
allowlist_strings = [
    # "AKIAIOSFODNN7EXAMPLE",
]

[retry]
# Retry network-heavy steps (pip install, npm ci, cargo fetch, etc.)
# on transient failures (timeouts, network resets, rate limits).
attempts     = 0    # 0 = disabled; maximum 5
backoff_base = 2.0  # seconds before first retry (doubles: 2s, 4s, 8s…)

[output]
# When set, write these regardless of CLI flags.
# sarif_path = "pipewarden.sarif"
# junit_path = "pipewarden-junit.xml"
# log_path   = "pipewarden.log"
color = true
quiet = false
```

---

## Environment Variable Overrides

All major settings can be overridden with `PIPEWARDEN_*` environment variables.
Priority: **CLI flags > env vars > `.pipewarden.toml` > built-in defaults**.

| Variable | Type | Equivalent config key |
|----------|------|-----------------------|
| `PIPEWARDEN_FAIL_FAST` | `1`/`true` | `fail_fast = true` |
| `PIPEWARDEN_SKIP` | comma-list | `skip = [...]` |
| `PIPEWARDEN_ONLY` | comma-list | `only = [...]` |
| `PIPEWARDEN_TIMEOUT_INSTALL_S` | integer | `timeouts.install_s` |
| `PIPEWARDEN_TIMEOUT_BUILD_S` | integer | `timeouts.build_s` |
| `PIPEWARDEN_TIMEOUT_TEST_S` | integer | `timeouts.test_s` |
| `PIPEWARDEN_TIMEOUT_SCAN_S` | integer | `timeouts.scan_s` |
| `PIPEWARDEN_TIMEOUT_DEFAULT_S` | integer | `timeouts.default_s` |
| `PIPEWARDEN_NO_COLOR` | `1`/`true` | `output.color = false` |
| `PIPEWARDEN_QUIET` | `1`/`true` | `output.quiet = true` |
| `PIPEWARDEN_RETRY_ATTEMPTS` | integer 0–5 | `retry.attempts` |
| `PIPEWARDEN_RETRY_BACKOFF` | float | `retry.backoff_base` |
