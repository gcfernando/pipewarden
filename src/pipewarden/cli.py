"""CLI entry point. Parses args, loads config, runs stages, writes reports."""
from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from io import TextIOWrapper
from pathlib import Path

from . import __version__
from .config import (
    ALL_STAGES,
    ConfigError,
    PipelineConfig,
    apply_env_overrides,
    find_config_file,
    load_config,
)
from .detect import detect
from .printer import Printer, print_summary
from .reporters import (
    to_github_annotations,
    to_json,
    to_junit_xml,
    to_markdown_summary,
    to_sarif,
)
from .secrets import scan_secrets
from .stages import STAGES
from .types import Report, Status, StepResult

log = logging.getLogger("pipewarden")


# ---------------------------------------------------------------------------
# Exit codes — stable, documented.
# ---------------------------------------------------------------------------
EXIT_OK          = 0   # all stages passed
EXIT_FAILURES    = 1   # one or more stages failed
EXIT_USAGE       = 2   # bad CLI arguments or --root not a directory
EXIT_CONFIG      = 3   # invalid .pipewarden.toml or env var value
EXIT_SECRETS     = 4   # secrets scan specifically found exposed credentials
EXIT_INTERRUPTED = 130 # SIGINT / KeyboardInterrupt


class _FailFast(Exception):
    """Used to abort the run loop when --fail-fast is set."""


def _setup_logging(log_path: str | None, verbose: bool) -> None:
    """Configure the root logger: write to a file and/or stderr depending on the flags."""
    handlers: list[logging.Handler] = []
    if log_path:
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))
    if verbose:
        handlers.append(logging.StreamHandler(sys.stderr))
    if not handlers:
        handlers.append(logging.NullHandler())
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse command-line arguments and return the populated namespace."""
    p = argparse.ArgumentParser(
        prog="pipewarden",
        description="Detect, install, lint, test, build, scan — locally or in CI.",
    )
    p.add_argument("--version", action="version", version=f"pipewarden {__version__}")
    p.add_argument("--root", type=Path, default=Path.cwd(),
                   help="project root (default: cwd)")
    p.add_argument("--config", type=Path, default=None,
                   help="path to a .pipewarden.toml (default: auto-discovered)")

    # Stage selection
    p.add_argument("--skip", action="append", default=[], choices=ALL_STAGES,
                   help="skip a stage (repeatable)")
    p.add_argument("--only", action="append", default=[], choices=ALL_STAGES,
                   help="run only these stages (repeatable)")

    # Run behaviour
    p.add_argument("--fail-fast", action="store_true",
                   help="abort on first failure")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would run without executing anything, then exit 0")
    p.add_argument("--diff", metavar="REF", default=None,
                   help="restrict scans to files changed vs REF (e.g. origin/main). "
                        "Currently affects the secrets stage.")

    # Introspection / setup
    p.add_argument("--init", action="store_true",
                   help="scaffold a .pipewarden.toml in --root and exit")
    p.add_argument("--validate", action="store_true",
                   help="validate the config file and exit (0 = valid, 3 = error)")
    p.add_argument("--list-stages", action="store_true",
                   help="list detected and enabled stages, then exit 0")

    # Output formats
    p.add_argument("--json", dest="json_to_stdout", action="store_true",
                   help="emit JSON report on stdout (suppresses pretty output)")
    p.add_argument("--sarif-out", type=Path, default=None,
                   help="write SARIF 2.1 file (for GitHub Code Scanning etc.)")
    p.add_argument("--junit-out", type=Path, default=None,
                   help="write JUnit XML file (for CI test parsers)")
    p.add_argument("--markdown-out", type=Path, default=None, metavar="PATH",
                   help="write Markdown summary (pipe to $GITHUB_STEP_SUMMARY)")
    p.add_argument("--gh-annotations", action="store_true",
                   help="print GitHub Actions inline annotations to stdout on findings")

    # Misc
    p.add_argument("--log-file", type=Path, default=None,
                   help="write debug log to this file")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--verbose", "-v", action="store_true", help="verbose logging to stderr")
    p.add_argument("--docker-tag", default=None,
                   help="override docker image tag")
    return p.parse_args(argv)


def merge_cli_into_config(cfg: PipelineConfig, args: argparse.Namespace) -> None:
    """CLI flags override config file values (highest precedence)."""
    if args.only:
        cfg.only = list(args.only)
    if args.skip:
        cfg.skip = list(args.skip)
    if args.fail_fast:
        cfg.fail_fast = True
    if args.json_to_stdout:
        cfg.output.quiet = True
    if args.no_color:
        cfg.output.color = False
    if args.docker_tag:
        cfg.docker_tag = args.docker_tag
    cfg.validate()


def _stage_enabled(name: str, cfg: PipelineConfig) -> bool:
    """Return True if the stage should run given the current --only/--skip/config state."""
    if cfg.only and name not in cfg.only:
        return False
    if name in cfg.skip:
        return False
    toggle = getattr(cfg.stages, name, None)
    return toggle is not False


# ---------------------------------------------------------------------------
# Utility actions (--init, --validate, --list-stages, --dry-run)
# ---------------------------------------------------------------------------

_INIT_TEMPLATE = """\
# .pipewarden.toml
# Full reference: https://github.com/gcfernando/pipewarden

[stages]
# Uncomment to disable specific stages:
# docker   = false
# vulns    = false
# outdated = true    # opt-in: check for outdated dependencies

[dotnet]
# format   = true   # dotnet format --verify-no-changes (code style)
# vulns    = true   # dotnet list package --vulnerable (CVE scan, built-in)
# outdated = false  # dotnet list package --outdated (non-blocking, opt-in)

[secrets]
# scan_history      = false  # scan full git history via gitleaks (opt-in)
# allowlist_paths   = ["tests/fixtures/**", ".pipewarden-venv/**"]
# allowlist_rules   = []
# allowlist_strings = []

[timeouts]
# install_s = 900
# build_s   = 900
# test_s    = 1800
# scan_s    = 600

[retry]
# attempts     = 0    # 0 = disabled, max 5
# backoff_base = 2.0  # seconds before first retry (doubles each attempt)
"""


def _cmd_init(root: Path) -> int:
    """Write a starter .pipewarden.toml to root, refusing to overwrite an existing one."""
    target = root / ".pipewarden.toml"
    if target.exists():
        print(f"error: {target} already exists — remove it first", file=sys.stderr)
        return EXIT_USAGE
    target.write_text(_INIT_TEMPLATE, encoding="utf-8")
    print(f"created {target}")
    return EXIT_OK


def _cmd_validate(cfg_path: Path | None) -> int:
    """Load and validate the config file, printing the outcome. Returns EXIT_OK or EXIT_CONFIG."""
    try:
        load_config(cfg_path)
        print(f"config OK: {cfg_path or '(defaults)'}")
        return EXIT_OK
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG


def _cmd_list_stages(root: Path, cfg: PipelineConfig) -> int:
    """Print a table showing which stages were detected and whether they are enabled."""
    d = detect(root)
    any_lang = bool(d.python or d.node or d.rust or d.go)
    detected_map = {
        "secrets": True,
        "python":  d.python,
        "node":    d.node,
        "dotnet":  d.dotnet,
        "go":      d.go,
        "rust":    d.rust,
        "docker":  d.docker,
        "vulns":   any_lang,
        "outdated": any_lang,
    }
    print(f"{'Stage':<12}  {'Detected':<10}  {'Enabled'}")
    print("-" * 38)
    for stage in ("secrets", "python", "node", "dotnet", "go", "rust", "docker", "vulns", "outdated"):
        det = "yes" if detected_map.get(stage) else "no"
        enabled = "yes" if (_stage_enabled(stage, cfg) and detected_map.get(stage)) else "no"
        if stage == "secrets":
            enabled = "yes" if _stage_enabled(stage, cfg) and cfg.secrets.enabled else "no"
        print(f"  {stage:<10}  {det:<10}  {enabled}")
    return EXIT_OK


def _cmd_dry_run(root: Path, cfg: PipelineConfig) -> int:
    """Print which stages would run without actually executing any of them."""
    d = detect(root)
    any_lang = bool(d.python or d.node or d.rust or d.go)
    detected_map = {
        "secrets":  True,
        "python":   d.python,
        "node":     d.node,
        "dotnet":   d.dotnet,
        "go":       d.go,
        "rust":     d.rust,
        "docker":   d.docker,
        "vulns":    any_lang,
        "outdated": any_lang,
    }
    print(f"Dry-run — detected: {', '.join(d.labels()) or '(nothing)'}\n")
    print(f"{'Stage':<12}  {'Would run?'}")
    print("-" * 30)
    for stage in ("secrets", "python", "node", "dotnet", "go", "rust", "docker", "vulns", "outdated"):
        det = detected_map.get(stage, False)
        if not det:
            reason = "not detected"
        elif not _stage_enabled(stage, cfg):
            reason = "disabled (--skip or config)"
        elif stage == "secrets" and not cfg.secrets.enabled:
            reason = "disabled in config"
        else:
            reason = "yes"
        print(f"  {stage:<10}  {reason}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Entry point for the pipewarden CLI. Returns a process exit code."""
    try:
        args = parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as e:
        return int(e.code) if e.code is not None else EXIT_USAGE

    # Ensure UTF-8 output on Windows where the default encoding may be cp1252.
    for _stream in (sys.stdout, sys.stderr):
        if isinstance(_stream, TextIOWrapper):
            _stream.reconfigure(encoding="utf-8", errors="replace")

    root: Path = args.root.resolve()
    if not root.is_dir():
        print(f"error: --root is not a directory: {root}", file=sys.stderr)
        return EXIT_USAGE

    _setup_logging(str(args.log_file) if args.log_file else None, args.verbose)

    # --init: scaffold config and exit before loading anything else.
    if args.init:
        return _cmd_init(root)

    # Load config: defaults → TOML → env vars → CLI flags (each layer wins over prior).
    cfg_path = args.config or find_config_file(root)
    try:
        cfg = load_config(cfg_path)
        apply_env_overrides(cfg)        # PIPEWARDEN_* env vars
        merge_cli_into_config(cfg, args)  # CLI flags (highest priority)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_CONFIG

    # --validate / --list-stages / --dry-run: introspection exits.
    if args.validate:
        return _cmd_validate(cfg_path)
    if args.list_stages:
        return _cmd_list_stages(root, cfg)
    if args.dry_run:
        return _cmd_dry_run(root, cfg)

    printer = Printer(quiet=cfg.output.quiet, color=cfg.output.color)
    report = Report(root=str(root), tool_version=__version__,
                    config_path=str(cfg_path) if cfg_path else None)
    started = time.monotonic()

    # SIGINT → KeyboardInterrupt so we can still print a summary.
    def _handle_sigint(_sig, _frame):  # type: ignore[no-untyped-def]  # pragma: no cover
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _handle_sigint)

    printer.section(f"Pipewarden {__version__}")
    d = detect(root)
    report.detected = d.labels()
    printer.info(f"root:     {root}")
    printer.info(f"config:   {cfg_path or '(defaults — no config file found)'}")
    printer.info(f"detected: {', '.join(d.labels()) or '(nothing recognized)'}")

    any_lang = bool(d.python or d.node or d.rust or d.go)
    detected_map = {
        "python": d.python, "node": d.node, "dotnet": d.dotnet,
        "go": d.go, "rust": d.rust, "docker": d.docker,
        "vulns":    any_lang,
        "outdated": any_lang,
    }

    try:
        # Secrets first — fast, and we want to stop early on a leak.
        if _stage_enabled("secrets", cfg) and cfg.secrets.enabled:
            printer.section("Secrets")
            r = scan_secrets(root, cfg.secrets, cfg.timeouts.scan_s,
                             diff_base=args.diff)
            report.add(r)
            _log_step(r, printer)
            if r.is_failure() and cfg.fail_fast:
                raise _FailFast()

        # Language stages
        for stage_name in ("python", "node", "dotnet", "go", "rust", "docker", "vulns", "outdated"):
            if not detected_map.get(stage_name):
                continue
            if not _stage_enabled(stage_name, cfg):
                report.add(StepResult(name=stage_name, status=Status.SKIPPED,
                                      message="disabled in config/flags"))
                continue
            printer.section(stage_name.upper() if stage_name == "vulns"
                            else stage_name.capitalize())
            before = len(report.steps)
            STAGES[stage_name](root, d, cfg, report.steps)
            for s in report.steps[before:]:
                _log_step(s, printer)
            if cfg.fail_fast and any(s.is_failure() for s in report.steps):
                raise _FailFast()

    except _FailFast:
        printer.warn("--fail-fast triggered; stopping.")
    except KeyboardInterrupt:  # pragma: no cover
        printer.warn("interrupted")
        report.duration_s = time.monotonic() - started
        _emit_outputs(report, cfg, args, printer)
        return EXIT_INTERRUPTED

    report.duration_s = time.monotonic() - started
    _emit_outputs(report, cfg, args, printer)

    if report.failed():
        secrets_failed = any(
            s.name.startswith("secrets") and s.is_failure()
            for s in report.steps
        )
        return EXIT_SECRETS if secrets_failed else EXIT_FAILURES
    return EXIT_OK


def _log_step(s: StepResult, printer: Printer) -> None:
    """Print a single step result in the appropriate color and icon."""
    if s.status == Status.PASSED:
        printer.ok(f"{s.name} ({s.duration_s:.1f}s)")
    elif s.status == Status.FAILED:
        printer.fail(f"{s.name}: {s.message}")
    elif s.status == Status.WARNED:
        printer.warn(f"{s.name}: {s.message}")
    else:
        printer.info(f"{s.name}: {s.message}")


def _emit_outputs(report: Report, cfg: PipelineConfig,
                  args: argparse.Namespace, printer: Printer) -> None:
    """Write all requested output formats: pretty summary, JSON, SARIF, JUnit XML, Markdown, and GHA annotations."""
    # JSON to stdout (--json) is mutually exclusive with the pretty summary.
    if cfg.output.quiet:
        sys.stdout.write(to_json(report))
        sys.stdout.write("\n")
    else:
        print_summary(report, printer)

    if args.sarif_out:
        try:
            args.sarif_out.write_text(to_sarif(report), encoding="utf-8")
        except OSError as e:
            print(f"warning: could not write SARIF: {e}", file=sys.stderr)

    if args.junit_out:
        try:
            args.junit_out.write_text(to_junit_xml(report), encoding="utf-8")
        except OSError as e:
            print(f"warning: could not write JUnit XML: {e}", file=sys.stderr)

    if args.markdown_out:
        try:
            args.markdown_out.write_text(to_markdown_summary(report), encoding="utf-8")
        except OSError as e:
            print(f"warning: could not write Markdown summary: {e}", file=sys.stderr)

    if args.gh_annotations:
        annotations = to_github_annotations(report)
        if annotations:
            print(annotations)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
