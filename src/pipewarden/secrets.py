"""Secret scanning.

Strategy:
  1. If `gitleaks` is installed and config.secrets.prefer_external is true,
     shell out to it. It's the de facto standard, kept up-to-date by experts.
  2. Otherwise, run a built-in regex scanner. This is intentionally
     conservative — high-precision patterns only, plus allowlist support.

The fallback is NEVER claimed to be exhaustive. We log a warning so users
know to install gitleaks for real coverage.
"""
from __future__ import annotations

import re
import shutil
import time
from collections.abc import Iterable
from pathlib import Path

from .config import SecretsConfig
from .runner import capture, run_cmd
from .types import Finding, Severity, Status, StepResult

IGNORED_DIR_NAMES = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "dist", "build", "target", "out", ".next", ".nuxt", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".gradle",
    "vendor", "bin", "obj", ".idea", ".vscode",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war",
    ".pyc", ".pyo", ".o", ".a", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac", ".webm",
}

# (rule_id, severity, regex).
# Conservative — high-signal. Avoids the generic "API_KEY=" substring trap.
SECRET_PATTERNS: list[tuple[str, Severity, re.Pattern[str]]] = [
    # AWS
    ("aws.access_key", Severity.CRITICAL,
        re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws.secret_key", Severity.CRITICAL,
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    # GitHub
    ("github.pat_classic", Severity.CRITICAL,
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github.pat_fine_grained", Severity.CRITICAL,
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("github.oauth", Severity.CRITICAL,
        re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    # GitLab
    ("gitlab.pat", Severity.CRITICAL,
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    # Communication / SaaS
    ("slack.token", Severity.HIGH,
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("twilio.account_sid", Severity.HIGH,
        re.compile(r"\bAC[a-f0-9]{32}\b")),
    ("sendgrid.api_key", Severity.HIGH,
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    # Google
    ("google.api_key", Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # Payment
    ("stripe.live_key", Severity.CRITICAL,
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("stripe.restricted", Severity.HIGH,
        re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    # Private keys / certificates
    ("private_key.pem", Severity.CRITICAL,
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    # Auth tokens
    ("jwt", Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    # Package registries
    ("npm.token", Severity.HIGH,
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi.api_token", Severity.HIGH,
        re.compile(r"\bpypi-[A-Za-z0-9_\-]{64,}\b")),
    # AI service APIs
    ("anthropic.api_key", Severity.CRITICAL,
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{40,}\b")),
    ("openai.api_key", Severity.CRITICAL,
        re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
    ("openai.api_key_project", Severity.CRITICAL,
        re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{100,}\b")),
    # Cloud platforms
    ("databricks.token", Severity.HIGH,
        re.compile(r"\bdapi[a-f0-9]{32}\b")),
    ("hashicorp.vault_token", Severity.HIGH,
        re.compile(r"\bhvs\.[A-Za-z0-9_\-]{24,}\b")),
    # Database connection strings
    ("mongodb.connection_string", Severity.CRITICAL,
        re.compile(r"mongodb(?:\+srv)?://[^:@\s]{1,100}:[^@\s]{1,200}@")),
]


def _compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a gitignore-style glob (supports **, *, ?) to a regex.

    Rules:
      **/  matches zero or more directory segments (including none).
      **   anywhere else matches any path including /.
      *    matches any sequence of non-/ chars.
      ?    matches any single non-/ char.
    """
    pattern = pattern.replace("\\", "/")
    i, n = 0, len(pattern)
    buf: list[str] = ["^"]
    while i < n:
        if pattern[i : i + 3] == "**/":
            buf.append("(.*/)?")
            i += 3
        elif pattern[i : i + 2] == "**":
            buf.append(".*")
            i += 2
        elif pattern[i] == "*":
            buf.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            buf.append("[^/]")
            i += 1
        else:
            buf.append(re.escape(pattern[i]))
            i += 1
    buf.append("$")
    return re.compile("".join(buf))


def _path_allowlisted(rel_path: str, compiled: list[re.Pattern[str]]) -> bool:
    """Return True if rel_path matches any precompiled allowlist pattern."""
    return any(rx.match(rel_path) for rx in compiled)


def iter_files(root: Path, max_files: int, diff_base: str | None = None) -> Iterable[Path]:
    """Yield candidate files for scanning.

    If `diff_base` is set (e.g. "origin/main"), only files changed vs that ref
    AND files that are untracked but exist on disk are scanned. Falls back to
    a full git ls-files / filesystem walk otherwise.

    Prefers git-aware listing so .gitignore is respected.
    """
    # Diff mode — only changed/untracked files. Designed for pre-push speed.
    if diff_base is not None:
        diff_out = capture(
            ["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMRTUXB",
             f"{diff_base}...HEAD"],
            cwd=root,
        )
        untracked_out = capture(
            ["git", "-C", str(root), "ls-files", "--others", "--exclude-standard"],
            cwd=root,
        )
        lines: list[str] = []
        if diff_out is not None:
            lines.extend(diff_out.splitlines())
        if untracked_out is not None:
            lines.extend(untracked_out.splitlines())
        seen: set[str] = set()
        count = 0
        for line in lines:
            if line in seen:
                continue
            seen.add(line)
            p = root / line
            if p.is_file():
                yield p
                count += 1
                if count >= max_files:
                    return
        return

    # Full scan — try git for .gitignore respect.
    out = capture(["git", "-C", str(root), "ls-files",
                   "--cached", "--others", "--exclude-standard"], cwd=root)
    if out is not None:
        count = 0
        for line in out.splitlines():
            p = (root / line)
            if p.is_file():
                yield p
                count += 1
                if count >= max_files:
                    return
        return

    # Fallback: filesystem walk
    count = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIR_NAMES for part in path.parts):
            continue
        yield path
        count += 1
        if count >= max_files:
            return


def scan_secrets_fallback(
    root: Path, cfg: SecretsConfig, diff_base: str | None = None
) -> StepResult:
    """Built-in regex scanner. Used when gitleaks is not available."""
    name = "secrets:fallback"
    start = time.monotonic()
    findings: list[Finding] = []
    scanned = 0
    rule_allow = set(cfg.allowlist_rules)
    string_allow = cfg.allowlist_strings
    # Precompile allowlist globs once — avoids re-compiling per file.
    allow_path_regexes = [_compile_glob(p) for p in cfg.allowlist_paths]

    for path in iter_files(root, cfg.max_files, diff_base=diff_base):
        rel = path.relative_to(root).as_posix()
        if _path_allowlisted(rel, allow_path_regexes):
            continue
        if path.suffix.lower() in BINARY_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > cfg.max_file_bytes:
                continue
            content = path.read_text(encoding="utf-8", errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        scanned += 1

        for rule_id, severity, pattern in SECRET_PATTERNS:
            if rule_id in rule_allow:
                continue
            for m in pattern.finditer(content):
                matched = m.group(0)
                if any(s in matched for s in string_allow):
                    continue
                line_no = content[: m.start()].count("\n") + 1
                col = m.start() - content.rfind("\n", 0, m.start())
                snippet = matched if len(matched) <= 16 else f"{matched[:4]}…{matched[-4:]}"
                findings.append(Finding(
                    rule_id=rule_id, message=f"possible {rule_id}",
                    severity=severity, file=rel, line=line_no,
                    column=max(col, 1), snippet=snippet,
                ))

    duration = time.monotonic() - start
    suffix = f" (diff vs {diff_base})" if diff_base else ""
    if findings:
        return StepResult(
            name=name, status=Status.FAILED, duration_s=duration,
            message=f"{len(findings)} possible secrets in {scanned} files{suffix}",
            findings=findings,
        )
    return StepResult(
        name=name, status=Status.PASSED, duration_s=duration,
        message=f"scanned {scanned} files, no secrets{suffix}",
    )


def scan_secrets(
    root: Path, cfg: SecretsConfig, timeout: int, diff_base: str | None = None
) -> StepResult:
    """Entry point. Prefers gitleaks, falls back to built-in scanner."""
    if cfg.prefer_external and shutil.which("gitleaks"):
        cmd = ["gitleaks", "detect", "--no-banner", "--redact", "--source", str(root)]
        # gitleaks doesn't natively scope by arbitrary ref range, so fall back
        # to the built-in scanner when a diff base is requested.
        if diff_base is not None:
            return scan_secrets_fallback(root, cfg, diff_base=diff_base)
        return run_cmd(cmd, cwd=root, name="secrets:gitleaks", timeout=timeout, required=True)
    return scan_secrets_fallback(root, cfg, diff_base=diff_base)
