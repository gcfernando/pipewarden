"""Per-language stage runners.

Each `run_*` function appends StepResults to the given list. It does NOT
raise on failure — failures are collected and returned for the summary.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict

from .config import DotnetConfig, PipelineConfig
from .detect import Detection
from .runner import run_cmd
from .types import Status, StepResult


class _RetryKw(TypedDict):
    """Keyword arguments forwarded to run_cmd for retry behaviour."""
    retries: int
    backoff_base: float


def _retry_kw(cfg: PipelineConfig) -> _RetryKw:
    """Return retry kwargs for network-heavy run_cmd calls."""
    return {"retries": cfg.retry.attempts, "backoff_base": cfg.retry.backoff_base}


def _in_ci() -> bool:
    """Return True when running inside a known CI environment."""
    return any(os.environ.get(v) for v in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD"))


def _docker_daemon_available() -> bool:
    """Return True if the Docker CLI is present and the daemon is responding."""
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def _pyproject_has_section(root: Path, dotted: str) -> bool:
    """Return True if pyproject.toml contains the given dotted TOML section (e.g. 'tool.mypy')."""
    if sys.version_info >= (3, 11):
        import tomllib
    else:  # pragma: no cover
        import tomli as tomllib  # type: ignore[no-redef,import-not-found,unused-ignore]
    pp = root / "pyproject.toml"
    if not pp.is_file():
        return False
    try:
        with pp.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return False
    node: object = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def run_python(root: Path, d: Detection, cfg: PipelineConfig,
               results: list[StepResult]) -> None:
    """Run the full Python pipeline: venv creation, dependency install, lint, typecheck, test.

    Uses an isolated .pipewarden-venv so it never touches the project's own
    virtual environment. Package manager is chosen automatically: uv > poetry > pip.
    """
    venv = root / ".pipewarden-venv"
    py = sys.executable

    if not venv.exists():
        r = run_cmd([py, "-m", "venv", str(venv)],
                    cwd=root, name="py:venv",
                    timeout=cfg.timeouts.install_s, required=True)
        results.append(r)
        if r.is_failure():
            return

    vpy = str(venv / "Scripts" / "python.exe") if os.name == "nt" else str(venv / "bin" / "python")

    # Pick installer: uv > poetry > pip
    if d.has_uv_lock and shutil.which("uv"):
        cmd = ["uv", "sync", "--frozen"]
        step_name = "py:deps(uv)"
    elif d.has_poetry_lock and shutil.which("poetry"):
        cmd = ["poetry", "install", "--no-interaction"]
        step_name = "py:deps(poetry)"
    elif d.has_pyproject:
        cmd = [vpy, "-m", "pip", "install", "--quiet", "-e", "."]
        step_name = "py:deps(pyproject)"
    elif d.has_requirements:
        cmd = [vpy, "-m", "pip", "install", "--quiet", "-r", "requirements.txt"]
        step_name = "py:deps(requirements)"
    else:
        results.append(StepResult(name="py:deps", status=Status.SKIPPED,
                                  message="no manifest"))
        return

    r = run_cmd(cmd, cwd=root, name=step_name,
                timeout=cfg.timeouts.install_s, required=True, **_retry_kw(cfg))
    results.append(r)
    if r.is_failure():
        return

    if shutil.which("ruff"):
        results.append(run_cmd(["ruff", "check", "."], cwd=root,
                               name="py:lint(ruff)",
                               timeout=cfg.timeouts.default_s, required=True))
    else:
        results.append(StepResult(name="py:lint", status=Status.SKIPPED,
                                  message="ruff not installed"))

    # mypy only if configured — running unconfigured mypy is noisy.
    if shutil.which("mypy") and (
        (root / "mypy.ini").exists() or _pyproject_has_section(root, "tool.mypy")
    ):
        results.append(run_cmd(["mypy", "."], cwd=root,
                               name="py:typecheck(mypy)",
                               timeout=cfg.timeouts.default_s, required=True))

    has_tests = (root / "tests").is_dir() or (root / "test").is_dir() \
                or _pyproject_has_section(root, "tool.pytest.ini_options")
    if has_tests:
        # Probe whether pytest is importable in the venv first. If not, emit a
        # clear WARNED step rather than running pytest just to get an opaque
        # "No module named pytest" error.
        probe = run_cmd([vpy, "-c", "import pytest"], cwd=root,
                        name="py:test(probe)", timeout=15, required=False,
                        stream=False)
        if probe.status != Status.PASSED:
            results.append(StepResult(
                name="py:test(pytest)", status=Status.WARNED,
                message="pytest not installed in the project — add it as a dep or skip this stage",
            ))
            return
        pytest_cmd = [vpy, "-m", "pytest", "-q"]
        results.append(run_cmd(pytest_cmd, cwd=root,
                               name="py:test(pytest)",
                               timeout=cfg.timeouts.test_s, required=True))


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

def _read_npm_scripts(root: Path) -> dict[str, str]:
    """Return the scripts dict from package.json, or an empty dict on any read/parse error."""
    try:
        with (root / "package.json").open("r", encoding="utf-8") as f:
            return dict(json.load(f).get("scripts") or {})
    except (OSError, json.JSONDecodeError):
        return {}


def run_node(root: Path, d: Detection, cfg: PipelineConfig,
             results: list[StepResult]) -> None:
    """Run the Node.js pipeline: install deps, then any lint/typecheck/test/build scripts found."""
    pm = d.node_pm
    if pm == "pnpm":
        install_cmd = ["pnpm", "install", "--frozen-lockfile"]
    elif pm == "yarn":
        install_cmd = ["yarn", "install", "--frozen-lockfile"]
    else:
        install_cmd = ["npm", "ci"] if d.has_package_lock else ["npm", "install"]

    r = run_cmd(install_cmd, cwd=root, name=f"node:deps({pm})",
                timeout=cfg.timeouts.install_s, required=True, **_retry_kw(cfg))
    results.append(r)
    if r.is_failure():
        return

    scripts = _read_npm_scripts(root)
    for script in ("lint", "typecheck", "test", "build"):
        if script not in scripts:
            results.append(StepResult(name=f"node:{script}", status=Status.SKIPPED,
                                      message=f"no '{script}' script"))
            continue
        cmd = ["npm", "test"] if (pm == "npm" and script == "test") else [pm, "run", script]
        timeout = cfg.timeouts.test_s if script == "test" else cfg.timeouts.build_s
        results.append(run_cmd(cmd, cwd=root, name=f"node:{script}",
                               timeout=timeout, required=True))


# ---------------------------------------------------------------------------
# .NET / Go / Rust
# ---------------------------------------------------------------------------

def run_dotnet(root: Path, _d: Detection, cfg: PipelineConfig,
               results: list[StepResult]) -> None:
    """Run the .NET pipeline: restore, optional format check, build, test, optional vuln/outdated scan."""
    dcfg: DotnetConfig = cfg.dotnet

    r = run_cmd(["dotnet", "restore"], cwd=root, name="dotnet:restore",
                timeout=cfg.timeouts.install_s, required=True, **_retry_kw(cfg))
    results.append(r)
    if r.is_failure():
        return

    if dcfg.format:
        results.append(run_cmd(
            ["dotnet", "format", "--verify-no-changes"],
            cwd=root, name="dotnet:format",
            timeout=cfg.timeouts.default_s, required=True))

    r = run_cmd(["dotnet", "build", "--no-restore", "--nologo"], cwd=root,
                name="dotnet:build", timeout=cfg.timeouts.build_s, required=True)
    results.append(r)
    if r.is_failure():
        return

    results.append(run_cmd(["dotnet", "test", "--no-build", "--nologo"],
                           cwd=root, name="dotnet:test",
                           timeout=cfg.timeouts.test_s, required=True))

    if dcfg.vulns:
        # Built-in CVE scan — no external tool required (.NET 8+ exits non-zero on findings).
        results.append(run_cmd(
            ["dotnet", "list", "package", "--vulnerable", "--include-transitive"],
            cwd=root, name="dotnet:vulns",
            timeout=cfg.timeouts.scan_s, required=True, **_retry_kw(cfg)))

    if dcfg.outdated:
        results.append(run_cmd(
            ["dotnet", "list", "package", "--outdated"],
            cwd=root, name="dotnet:outdated",
            timeout=cfg.timeouts.scan_s, required=False, **_retry_kw(cfg)))


def run_go(root: Path, _d: Detection, cfg: PipelineConfig,
           results: list[StepResult]) -> None:
    """Run the Go pipeline: module download, vet, build, test."""
    results.append(run_cmd(["go", "mod", "download"], cwd=root, name="go:deps",
                           timeout=cfg.timeouts.install_s, required=True,
                           **_retry_kw(cfg)))
    if results[-1].is_failure():
        return
    results.append(run_cmd(["go", "vet", "./..."], cwd=root, name="go:vet",
                           timeout=cfg.timeouts.default_s, required=True))
    results.append(run_cmd(["go", "build", "./..."], cwd=root, name="go:build",
                           timeout=cfg.timeouts.build_s, required=True))
    results.append(run_cmd(["go", "test", "./..."], cwd=root, name="go:test",
                           timeout=cfg.timeouts.test_s, required=True))


def run_rust(root: Path, _d: Detection, cfg: PipelineConfig,
             results: list[StepResult]) -> None:
    """Run the Rust pipeline: crate fetch, Clippy lint, build, test."""
    results.append(run_cmd(["cargo", "fetch"], cwd=root, name="rust:deps",
                           timeout=cfg.timeouts.install_s, required=True,
                           **_retry_kw(cfg)))
    if results[-1].is_failure():
        return
    if shutil.which("cargo-clippy"):
        results.append(run_cmd(
            ["cargo", "clippy", "--all-targets", "--", "-D", "warnings"],
            cwd=root, name="rust:lint(clippy)",
            timeout=cfg.timeouts.build_s, required=True))
    results.append(run_cmd(["cargo", "build", "--all-targets"], cwd=root,
                           name="rust:build", timeout=cfg.timeouts.build_s,
                           required=True))
    results.append(run_cmd(["cargo", "test", "--all-targets"], cwd=root,
                           name="rust:test", timeout=cfg.timeouts.test_s,
                           required=True))


# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

def _run_container_scan(tag: str, root: Path, cfg: PipelineConfig,
                        results: list[StepResult]) -> None:
    """Best-effort container image CVE scan. Uses trivy or grype if on PATH."""
    if shutil.which("trivy"):
        results.append(run_cmd(
            ["trivy", "image", "--exit-code", "1", "--severity", "HIGH,CRITICAL", tag],
            cwd=root, name="docker:scan(trivy)",
            timeout=cfg.timeouts.scan_s, required=False))
    elif shutil.which("grype"):
        results.append(run_cmd(
            ["grype", tag, "--fail-on", "high"],
            cwd=root, name="docker:scan(grype)",
            timeout=cfg.timeouts.scan_s, required=False))


def run_docker(root: Path, d: Detection, cfg: PipelineConfig,
               results: list[StepResult]) -> None:
    """Run the Docker pipeline: hadolint lint, image build, and optional container CVE scan."""
    dockerfile = d.dockerfile_name
    if shutil.which("hadolint"):
        results.append(run_cmd(["hadolint", dockerfile], cwd=root,
                               name="docker:lint(hadolint)",
                               timeout=cfg.timeouts.default_s, required=True))

    if not _docker_daemon_available():
        # In CI environments Docker is often intentionally absent (e.g. when
        # running in a rootless container). Downgrade to a warning so the
        # overall run isn't marked as failed just because the daemon is absent.
        status = Status.WARNED if _in_ci() else Status.FAILED
        msg = "Docker daemon not available"
        if _in_ci():
            msg += " — skipping build (CI environment without Docker socket)"
        results.append(StepResult(name="docker:build", status=status, message=msg))
        return

    build_result = run_cmd(
        ["docker", "build", "-t", cfg.docker_tag, "-f", dockerfile, "."],
        cwd=root, name="docker:build", timeout=cfg.timeouts.build_s, required=True)
    results.append(build_result)

    if not build_result.is_failure():
        _run_container_scan(cfg.docker_tag, root, cfg, results)


# ---------------------------------------------------------------------------
# Vulnerability scanning (cross-language)
# ---------------------------------------------------------------------------

def run_vulns(root: Path, d: Detection, cfg: PipelineConfig,
              results: list[StepResult]) -> None:
    """Best-effort dep vuln scan using whatever tools are on PATH.

    Most teams will plug in their preferred scanner; this is a useful default.
    """
    any_ran = False
    if d.python and shutil.which("pip-audit"):
        results.append(run_cmd(["pip-audit", "--strict"], cwd=root,
                               name="vulns:pip-audit",
                               timeout=cfg.timeouts.scan_s, required=False,
                               **_retry_kw(cfg)))
        any_ran = True
    if d.node and shutil.which("npm"):
        results.append(run_cmd(
            ["npm", "audit", "--audit-level=high", "--omit=dev"],
            cwd=root, name="vulns:npm-audit",
            timeout=cfg.timeouts.scan_s, required=False,
            **_retry_kw(cfg)))
        any_ran = True
    if d.rust and shutil.which("cargo-audit"):
        results.append(run_cmd(["cargo", "audit"], cwd=root, name="vulns:cargo-audit",
                               timeout=cfg.timeouts.scan_s, required=False,
                               **_retry_kw(cfg)))
        any_ran = True
    if d.go and shutil.which("govulncheck"):
        results.append(run_cmd(["govulncheck", "./..."], cwd=root,
                               name="vulns:govulncheck",
                               timeout=cfg.timeouts.scan_s, required=False,
                               **_retry_kw(cfg)))
        any_ran = True
    if not any_ran:
        results.append(StepResult(name="vulns", status=Status.SKIPPED,
                                  message="no vuln scanner available"))


# ---------------------------------------------------------------------------
# Outdated dependency checking (opt-in, all steps non-blocking)
# ---------------------------------------------------------------------------

def run_outdated(root: Path, d: Detection, cfg: PipelineConfig,
                 results: list[StepResult]) -> None:
    """Report outdated dependencies across detected language ecosystems.

    All steps are WARNED (non-blocking) — findings are informational.
    Python requires the project venv to exist (run the python stage first).
    """
    any_ran = False

    if d.python:
        venv = root / ".pipewarden-venv"
        if venv.is_dir():
            vpy = str(venv / "Scripts" / "python.exe") if os.name == "nt" \
                else str(venv / "bin" / "python")
            results.append(run_cmd(
                [vpy, "-m", "pip", "list", "--outdated"],
                cwd=root, name="outdated:python(pip)",
                timeout=cfg.timeouts.scan_s, required=False, **_retry_kw(cfg)))
            any_ran = True
        else:
            results.append(StepResult(
                name="outdated:python(pip)", status=Status.SKIPPED,
                message="venv not found — run the python stage first"))

    if d.node and shutil.which("npm"):
        # npm outdated exits non-zero when packages are outdated; required=False
        # treats that as WARNED rather than FAILED.
        results.append(run_cmd(
            ["npm", "outdated"],
            cwd=root, name="outdated:node(npm)",
            timeout=cfg.timeouts.scan_s, required=False))
        any_ran = True

    if d.go and shutil.which("go"):
        results.append(run_cmd(
            ["go", "list", "-m", "-u", "all"],
            cwd=root, name="outdated:go",
            timeout=cfg.timeouts.scan_s, required=False, **_retry_kw(cfg)))
        any_ran = True

    if d.rust and shutil.which("cargo-outdated"):
        results.append(run_cmd(
            ["cargo", "outdated"],
            cwd=root, name="outdated:rust(cargo-outdated)",
            timeout=cfg.timeouts.scan_s, required=False))
        any_ran = True

    if not any_ran:
        results.append(StepResult(
            name="outdated", status=Status.SKIPPED,
            message="no supported language detected or no outdated checker available"))


# Stage registry — drives main loop. Order matters.
STAGES: dict[str, Callable[..., None]] = {
    "python":   run_python,
    "node":     run_node,
    "dotnet":   run_dotnet,
    "go":       run_go,
    "rust":     run_rust,
    "docker":   run_docker,
    "vulns":    run_vulns,
    "outdated": run_outdated,
}
