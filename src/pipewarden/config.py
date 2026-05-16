"""Configuration loading and validation.

Config sources, in precedence order (later wins):
  1. Built-in defaults
  2. .pipewarden.toml in the project root
  3. CLI flags
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef,import-not-found,unused-ignore]


# Stages must match the names used by the runner.
ALL_STAGES = ("secrets", "vulns", "python", "node", "dotnet", "go", "rust", "docker")


class ConfigError(ValueError):
    """Raised when the user-supplied config is invalid."""


@dataclass
class SecretsConfig:
    enabled: bool = True
    prefer_external: bool = True   # use gitleaks if installed
    allowlist_paths: list[str] = field(default_factory=list)
    allowlist_rules: list[str] = field(default_factory=list)
    allowlist_strings: list[str] = field(default_factory=list)
    max_file_bytes: int = 1_000_000
    max_files: int = 10_000


@dataclass
class StageToggles:
    python: bool = True
    node: bool = True
    dotnet: bool = True
    go: bool = True
    rust: bool = True
    docker: bool = True
    vulns: bool = True


@dataclass
class TimeoutsConfig:
    install_s: int = 900
    build_s: int = 900
    test_s: int = 1800
    scan_s: int = 600
    default_s: int = 600


@dataclass
class OutputConfig:
    json_path: str | None = None
    sarif_path: str | None = None
    junit_path: str | None = None
    log_path: str | None = None
    color: bool = True
    quiet: bool = False


@dataclass
class RetryConfig:
    attempts: int = 0          # 0 = disabled; capped at 5 by validate()
    backoff_base: float = 2.0  # seconds before first retry; doubles each attempt


@dataclass
class PipelineConfig:
    """Top-level config."""
    fail_fast: bool = False
    only: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)
    docker_tag: str = "pipewarden-local:latest"
    stages: StageToggles = field(default_factory=StageToggles)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    timeouts: TimeoutsConfig = field(default_factory=TimeoutsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)

    def validate(self) -> None:
        """Raise ConfigError on invalid combinations."""
        for s in self.only:
            if s not in ALL_STAGES:
                raise ConfigError(f"unknown stage in 'only': {s!r}")
        for s in self.skip:
            if s not in ALL_STAGES:
                raise ConfigError(f"unknown stage in 'skip': {s!r}")
        for tname in ("install_s", "build_s", "test_s", "scan_s", "default_s"):
            v = getattr(self.timeouts, tname)
            if not isinstance(v, int) or v <= 0:
                raise ConfigError(f"timeouts.{tname} must be a positive integer, got {v!r}")
        if self.secrets.max_file_bytes <= 0:
            raise ConfigError("secrets.max_file_bytes must be positive")
        if self.secrets.max_files <= 0:
            raise ConfigError("secrets.max_files must be positive")
        if not 0 <= self.retry.attempts <= 5:
            raise ConfigError("retry.attempts must be between 0 and 5")
        if self.retry.backoff_base <= 0:
            raise ConfigError("retry.backoff_base must be a positive number")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

CONFIG_FILENAMES = (".pipewarden.toml", "pipewarden.toml")


def find_config_file(root: Path) -> Path | None:
    for name in CONFIG_FILENAMES:
        p = root / name
        if p.is_file():
            return p
    return None


def _coerce_into(target: Any, data: dict[str, Any], path: str) -> None:
    """Copy known keys from `data` into the dataclass `target`. Reject unknowns."""
    known = {f.name for f in fields(target)}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"unknown key: {path}.{key}")
        current = getattr(target, key)
        # Nested dataclass
        if hasattr(current, "__dataclass_fields__") and isinstance(value, dict):
            _coerce_into(current, value, f"{path}.{key}")
        else:
            # Type sanity (light — we don't ship a full schema validator)
            expected_type = type(current) if current is not None else None
            if expected_type is bool and not isinstance(value, bool):
                raise ConfigError(f"{path}.{key} must be a boolean")
            if expected_type is int and not isinstance(value, int):
                raise ConfigError(f"{path}.{key} must be an integer")
            if expected_type is str and not isinstance(value, str):
                raise ConfigError(f"{path}.{key} must be a string")
            if expected_type is list and not isinstance(value, list):
                raise ConfigError(f"{path}.{key} must be a list")
            setattr(target, key, value)


def load_config(path: Path | None) -> PipelineConfig:
    """Load config from a TOML file (or return defaults if path is None)."""
    cfg = PipelineConfig()
    if path is None:
        cfg.validate()
        return cfg
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML in {path}: {e}") from e

    _coerce_into(cfg, data, "pipewarden")
    cfg.validate()
    return cfg


# ---------------------------------------------------------------------------
# Environment variable overrides
# Priority: CLI flags > env vars > .toml file > built-in defaults
# ---------------------------------------------------------------------------

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def apply_env_overrides(cfg: PipelineConfig) -> None:
    """Overlay PIPEWARDEN_* environment variables onto a loaded config.

    Call this after load_config() and before merge_cli_into_config() so that
    CLI flags still take final precedence.
    """
    env = os.environ

    if env.get("PIPEWARDEN_FAIL_FAST", "").strip().lower() in _TRUTHY:
        cfg.fail_fast = True

    if raw := env.get("PIPEWARDEN_SKIP", "").strip():
        cfg.skip = [s.strip() for s in raw.split(",") if s.strip()]

    if raw := env.get("PIPEWARDEN_ONLY", "").strip():
        cfg.only = [s.strip() for s in raw.split(",") if s.strip()]

    for tname in ("install_s", "build_s", "test_s", "scan_s", "default_s"):
        key = f"PIPEWARDEN_TIMEOUT_{tname.upper()}"
        if raw := env.get(key, "").strip():
            try:
                setattr(cfg.timeouts, tname, int(raw))
            except ValueError:
                raise ConfigError(f"{key} must be an integer, got {raw!r}") from None

    if env.get("PIPEWARDEN_NO_COLOR", "").strip().lower() in _TRUTHY:
        cfg.output.color = False

    if env.get("PIPEWARDEN_QUIET", "").strip().lower() in _TRUTHY:
        cfg.output.quiet = True

    if raw := env.get("PIPEWARDEN_RETRY_ATTEMPTS", "").strip():
        try:
            cfg.retry.attempts = int(raw)
        except ValueError:
            raise ConfigError(
                f"PIPEWARDEN_RETRY_ATTEMPTS must be an integer, got {raw!r}"
            ) from None

    if raw := env.get("PIPEWARDEN_RETRY_BACKOFF", "").strip():
        try:
            cfg.retry.backoff_base = float(raw)
        except ValueError:
            raise ConfigError(
                f"PIPEWARDEN_RETRY_BACKOFF must be a number, got {raw!r}"
            ) from None
