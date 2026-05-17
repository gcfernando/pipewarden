"""Tests for config loading, env-var overrides, and validation — verifies the full config layer stack."""
from pathlib import Path

import pytest

from pipewarden.config import (
    ALL_STAGES,
    ConfigError,
    DotnetConfig,
    PipelineConfig,
    apply_env_overrides,
    find_config_file,
    load_config,
)


def test_defaults_are_valid() -> None:
    """Loading with no config file should return a valid PipelineConfig with sensible defaults."""
    cfg = load_config(None)
    assert isinstance(cfg, PipelineConfig)
    assert cfg.secrets.enabled
    assert cfg.timeouts.install_s > 0
    assert cfg.fail_fast is False


def test_find_config_file_missing(tmp_path: Path) -> None:
    """find_config_file should return None when no config file exists in the directory."""
    assert find_config_file(tmp_path) is None


def test_find_config_file_present(tmp_path: Path) -> None:
    """find_config_file should return the path when a .pipewarden.toml exists."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text("")
    assert find_config_file(tmp_path) == p


def test_load_simple_config(tmp_path: Path) -> None:
    """All top-level and section fields should be parsed and applied correctly from TOML."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text(
        'fail_fast = true\n'
        'docker_tag = "myapp:ci"\n'
        '[stages]\n'
        'docker = false\n'
        '[timeouts]\n'
        'install_s = 60\n'
        '[secrets]\n'
        'enabled = false\n'
        'allowlist_paths = ["tests/fixtures/*"]\n'
    )
    cfg = load_config(p)
    assert cfg.fail_fast
    assert cfg.docker_tag == "myapp:ci"
    assert cfg.stages.docker is False
    assert cfg.timeouts.install_s == 60
    assert cfg.secrets.enabled is False
    assert cfg.secrets.allowlist_paths == ["tests/fixtures/*"]


def test_unknown_key_rejected(tmp_path: Path) -> None:
    """A TOML key that does not map to any known config field should raise ConfigError."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text('bogus_key = 1\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_unknown_stage_rejected(tmp_path: Path) -> None:
    """A stage name in the skip list that is not in ALL_STAGES should raise ConfigError."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text('skip = ["nope"]\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_bad_type_rejected(tmp_path: Path) -> None:
    """A string where an integer is expected should raise ConfigError."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text('[timeouts]\ninstall_s = "fast"\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_invalid_timeout_value(tmp_path: Path) -> None:
    """A timeout of zero should be rejected as an invalid value."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text('[timeouts]\ninstall_s = 0\n')
    with pytest.raises(ConfigError):
        load_config(p)


def test_malformed_toml(tmp_path: Path) -> None:
    """A file with invalid TOML syntax should raise ConfigError rather than crash."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text('this is not [valid')
    with pytest.raises(ConfigError):
        load_config(p)


# ---------------------------------------------------------------------------
# apply_env_overrides
# ---------------------------------------------------------------------------

def test_apply_env_fail_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_FAIL_FAST=1 should enable fail_fast mode."""
    monkeypatch.setenv("PIPEWARDEN_FAIL_FAST", "1")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.fail_fast is True


def test_apply_env_fail_fast_truthy_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_FAIL_FAST=yes should also be treated as truthy."""
    monkeypatch.setenv("PIPEWARDEN_FAIL_FAST", "yes")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.fail_fast is True


def test_apply_env_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_SKIP should accept a comma-separated list of stage names."""
    monkeypatch.setenv("PIPEWARDEN_SKIP", "docker,vulns")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert "docker" in cfg.skip
    assert "vulns" in cfg.skip


def test_apply_env_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_ONLY should restrict the run to the specified stage."""
    monkeypatch.setenv("PIPEWARDEN_ONLY", "python")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.only == ["python"]


def test_apply_env_timeout_test_s(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_TIMEOUT_TEST_S should override the test stage timeout."""
    monkeypatch.setenv("PIPEWARDEN_TIMEOUT_TEST_S", "9999")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.timeouts.test_s == 9999


def test_apply_env_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_NO_COLOR=1 should disable colored output."""
    monkeypatch.setenv("PIPEWARDEN_NO_COLOR", "1")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.output.color is False


def test_apply_env_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_QUIET=true should enable quiet (JSON-only) output mode."""
    monkeypatch.setenv("PIPEWARDEN_QUIET", "true")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.output.quiet is True


def test_apply_env_retry_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_RETRY_ATTEMPTS should set the retry attempt count."""
    monkeypatch.setenv("PIPEWARDEN_RETRY_ATTEMPTS", "3")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.retry.attempts == 3


def test_apply_env_retry_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIPEWARDEN_RETRY_BACKOFF should set the backoff base in seconds."""
    monkeypatch.setenv("PIPEWARDEN_RETRY_BACKOFF", "5.0")
    cfg = load_config(None)
    apply_env_overrides(cfg)
    assert cfg.retry.backoff_base == 5.0


def test_apply_env_bad_timeout_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-numeric timeout env var should raise ConfigError with a clear message."""
    monkeypatch.setenv("PIPEWARDEN_TIMEOUT_INSTALL_S", "not-a-number")
    cfg = load_config(None)
    with pytest.raises(ConfigError, match="must be an integer"):
        apply_env_overrides(cfg)


def test_apply_env_bad_retry_attempts_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-integer PIPEWARDEN_RETRY_ATTEMPTS should raise ConfigError."""
    monkeypatch.setenv("PIPEWARDEN_RETRY_ATTEMPTS", "bad")
    cfg = load_config(None)
    with pytest.raises(ConfigError, match="must be an integer"):
        apply_env_overrides(cfg)


def test_apply_env_bad_retry_backoff_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-numeric PIPEWARDEN_RETRY_BACKOFF should raise ConfigError."""
    monkeypatch.setenv("PIPEWARDEN_RETRY_BACKOFF", "bad")
    cfg = load_config(None)
    with pytest.raises(ConfigError, match="must be a number"):
        apply_env_overrides(cfg)


def test_retry_invalid_attempts_raises() -> None:
    """retry.attempts above the maximum of 5 should fail validation."""
    cfg = load_config(None)
    cfg.retry.attempts = 6
    with pytest.raises(ConfigError, match=r"retry\.attempts"):
        cfg.validate()


def test_retry_invalid_backoff_raises() -> None:
    """retry.backoff_base of zero should fail validation."""
    cfg = load_config(None)
    cfg.retry.backoff_base = 0.0
    with pytest.raises(ConfigError, match=r"retry\.backoff_base"):
        cfg.validate()


# ---------------------------------------------------------------------------
# DotnetConfig
# ---------------------------------------------------------------------------

def test_dotnet_config_defaults() -> None:
    """DotnetConfig defaults should enable format and vulns, and disable outdated."""
    cfg = load_config(None)
    assert isinstance(cfg.dotnet, DotnetConfig)
    assert cfg.dotnet.format is True
    assert cfg.dotnet.vulns is True
    assert cfg.dotnet.outdated is False


def test_dotnet_config_loaded_from_toml(tmp_path: Path) -> None:
    """All three [dotnet] booleans should be read correctly from TOML."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text(
        "[dotnet]\n"
        "format = false\n"
        "vulns = false\n"
        "outdated = true\n"
    )
    cfg = load_config(p)
    assert cfg.dotnet.format is False
    assert cfg.dotnet.vulns is False
    assert cfg.dotnet.outdated is True


def test_dotnet_config_unknown_key_rejected(tmp_path: Path) -> None:
    """An unrecognised key inside [dotnet] should raise ConfigError."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text("[dotnet]\nbogus = true\n")
    with pytest.raises(ConfigError):
        load_config(p)


# ---------------------------------------------------------------------------
# scan_history
# ---------------------------------------------------------------------------

def test_scan_history_defaults_false() -> None:
    """scan_history should default to False so full git history scanning is opt-in."""
    cfg = load_config(None)
    assert cfg.secrets.scan_history is False


def test_scan_history_loaded_from_toml(tmp_path: Path) -> None:
    """scan_history = true in [secrets] should enable full git history scanning."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text("[secrets]\nscan_history = true\n")
    cfg = load_config(p)
    assert cfg.secrets.scan_history is True


# ---------------------------------------------------------------------------
# outdated stage toggle
# ---------------------------------------------------------------------------

def test_outdated_stage_in_all_stages() -> None:
    """The outdated stage should be listed in ALL_STAGES so it can be skipped/selected by name."""
    assert "outdated" in ALL_STAGES


def test_outdated_stage_disabled_by_default() -> None:
    """The outdated stage should be opt-in, so it defaults to False."""
    cfg = load_config(None)
    assert cfg.stages.outdated is False


def test_outdated_stage_enabled_via_toml(tmp_path: Path) -> None:
    """Setting outdated = true in [stages] should enable the outdated check."""
    p = tmp_path / ".pipewarden.toml"
    p.write_text("[stages]\noutdated = true\n")
    cfg = load_config(p)
    assert cfg.stages.outdated is True
