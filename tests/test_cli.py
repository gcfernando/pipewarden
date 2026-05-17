"""End-to-end CLI tests — exercises main() from argument parsing through report output."""
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from pipewarden.cli import EXIT_SECRETS, _cmd_validate, main


def test_help_runs(capsys: pytest.CaptureFixture[str]) -> None:
    """--help should exit 0 and print the program name and key flags."""
    rc = main(["--help"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pipewarden" in out
    assert "--sarif-out" in out


def test_version_runs(capsys: pytest.CaptureFixture[str]) -> None:
    """--version should exit 0 and print a version string containing 'pipewarden'."""
    rc = main(["--version"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pipewarden" in out


def test_empty_dir_succeeds(tmp_path: Path) -> None:
    """Running against an empty directory should pass (only the secrets stage runs and finds nothing)."""
    rc = main(["--root", str(tmp_path)])
    assert rc == 0


def test_bad_root_returns_usage_error(tmp_path: Path,
                                     capsys: pytest.CaptureFixture[str]) -> None:
    """A --root path that does not exist should return exit code 2 with an error message."""
    rc = main(["--root", str(tmp_path / "does-not-exist")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not a directory" in err


def test_json_output_on_empty(tmp_path: Path,
                              capsys: pytest.CaptureFixture[str]) -> None:
    """--json should emit valid JSON on stdout with the correct root path and step count."""
    rc = main(["--root", str(tmp_path), "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["root"] == str(tmp_path.resolve())
    assert data["summary"]["total"] >= 1  # secrets scan ran


def test_secret_leak_fails(tmp_path: Path) -> None:
    """A file containing an AWS access key should trigger EXIT_SECRETS (4)."""
    (tmp_path / "leak.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'\n")
    rc = main(["--root", str(tmp_path), "--no-color"])
    assert rc == EXIT_SECRETS


def test_skip_disables_stage(tmp_path: Path) -> None:
    """--skip secrets should bypass the scan so a leaky file does not cause a failure."""
    (tmp_path / "leak.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'\n")
    rc = main(["--root", str(tmp_path), "--skip", "secrets"])
    assert rc == 0


def test_sarif_output_written(tmp_path: Path) -> None:
    """--sarif-out should write a valid SARIF 2.1.0 file containing the detected finding."""
    (tmp_path / "leak.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'\n")
    sarif_path = tmp_path / "out.sarif"
    rc = main(["--root", str(tmp_path), "--sarif-out", str(sarif_path)])
    assert rc == EXIT_SECRETS
    data = json.loads(sarif_path.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]  # at least one finding


def test_junit_output_written(tmp_path: Path) -> None:
    """--junit-out should write a file containing a <testsuites> XML element."""
    junit_path = tmp_path / "junit.xml"
    rc = main(["--root", str(tmp_path), "--junit-out", str(junit_path)])
    assert rc == 0
    content = junit_path.read_text()
    assert "<testsuites" in content


def test_config_file_loaded(tmp_path: Path) -> None:
    """A .pipewarden.toml disabling secrets should prevent a leaky file from failing the run."""
    (tmp_path / ".pipewarden.toml").write_text("[secrets]\nenabled = false\n")
    (tmp_path / "leak.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'\n")
    rc = main(["--root", str(tmp_path)])
    assert rc == 0


def test_bad_config_returns_config_error(tmp_path: Path,
                                         capsys: pytest.CaptureFixture[str]) -> None:
    """A .pipewarden.toml with an unknown key should return exit code 3 with a config error message."""
    (tmp_path / ".pipewarden.toml").write_text("bogus = 1\n")
    rc = main(["--root", str(tmp_path)])
    assert rc == 3
    err = capsys.readouterr().err
    assert "config error" in err


def test_invoked_as_module(tmp_path: Path) -> None:
    """python -m pipewarden should be a working entry point that exits 0 on an empty directory."""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pipewarden", "--root", str(tmp_path), "--no-color"],
        capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr


def test_init_creates_config(tmp_path: Path) -> None:
    """--init should scaffold a .pipewarden.toml that mentions [dotnet], scan_history, and outdated."""
    rc = main(["--init", "--root", str(tmp_path)])
    assert rc == 0
    content = (tmp_path / ".pipewarden.toml").read_text()
    assert "[dotnet]" in content
    assert "scan_history" in content
    assert "outdated" in content


def test_init_fails_if_config_exists(tmp_path: Path,
                                      capsys: pytest.CaptureFixture[str]) -> None:
    """--init should refuse to overwrite an existing .pipewarden.toml and return exit code 2."""
    (tmp_path / ".pipewarden.toml").write_text("[secrets]\n")
    rc = main(["--init", "--root", str(tmp_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "already exists" in err


def test_validate_defaults(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--validate with no config file should report 'config OK' and return exit code 0."""
    rc = main(["--validate", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "config OK" in out


def test_validate_bad_config_directly(tmp_path: Path,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    """_cmd_validate on a bad TOML file should return exit code 3 and print a config error."""
    bad = tmp_path / "bad.toml"
    bad.write_text("bogus_key = 1\n")
    rc = _cmd_validate(bad)
    assert rc == 3
    err = capsys.readouterr().err
    assert "config error" in err


def test_list_stages_empty_project(tmp_path: Path,
                                    capsys: pytest.CaptureFixture[str]) -> None:
    """--list-stages should print a table that includes 'secrets', 'Stage', and 'outdated'."""
    rc = main(["--list-stages", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "secrets" in out
    assert "Stage" in out
    assert "outdated" in out


def test_dry_run_empty_project(tmp_path: Path,
                                capsys: pytest.CaptureFixture[str]) -> None:
    """--dry-run should print which stages would run without executing anything."""
    rc = main(["--dry-run", "--root", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Dry-run" in out
    assert "secrets" in out
    assert "outdated" in out


def test_dry_run_with_skip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--dry-run with --skip secrets should show the secrets stage as 'disabled'."""
    rc = main(["--dry-run", "--root", str(tmp_path), "--skip", "secrets"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "disabled" in out


def test_markdown_out_written(tmp_path: Path) -> None:
    """--markdown-out should write a Markdown file containing 'Pipewarden'."""
    md_path = tmp_path / "summary.md"
    rc = main(["--root", str(tmp_path), "--markdown-out", str(md_path)])
    assert rc == 0
    content = md_path.read_text(encoding="utf-8")
    assert "Pipewarden" in content


def test_gh_annotations_with_findings(tmp_path: Path,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    """--gh-annotations should print a ::error annotation to stdout for each finding."""
    (tmp_path / "leak.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'\n")
    rc = main(["--root", str(tmp_path), "--gh-annotations", "--no-color"])
    assert rc == EXIT_SECRETS
    out = capsys.readouterr().out
    assert "::error" in out


def test_verbose_flag(tmp_path: Path) -> None:
    """--verbose should not crash the run; it only enables debug logging to stderr."""
    rc = main(["--root", str(tmp_path), "--verbose"])
    assert rc == 0


def test_log_file_flag(tmp_path: Path) -> None:
    """--log-file should write a log file at the specified path."""
    log_path = tmp_path / "run.log"
    rc = main(["--root", str(tmp_path), "--log-file", str(log_path)])
    assert rc == 0
    assert log_path.exists()
    for h in logging.root.handlers[:]:
        h.close()
        logging.root.removeHandler(h)


def test_diff_mode_scopes_to_changed_files(tmp_path: Path) -> None:
    """--diff base limits the secret scan to git-changed files only."""
    import subprocess as sp
    # Init a git repo with a clean baseline commit, then add a leaky file unstaged.
    sp.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    sp.run(["git", "config", "user.email", "test@test"], cwd=tmp_path, check=True)
    sp.run(["git", "config", "user.name", "test"], cwd=tmp_path, check=True)
    (tmp_path / "clean.py").write_text("print('ok')\n")
    sp.run(["git", "add", "."], cwd=tmp_path, check=True)
    sp.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)

    # Now add a leak as an UNTRACKED file (diff mode should still catch it).
    (tmp_path / "leak.py").write_text("KEY='AKIAIOSFODNN7EXAMPLE'\n")

    rc = main(["--root", str(tmp_path), "--diff", "HEAD", "--no-color"])
    assert rc == EXIT_SECRETS  # the leak in the untracked file should be found
