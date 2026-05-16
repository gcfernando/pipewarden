import sys
from pathlib import Path
from unittest.mock import patch

from pipewarden.runner import _is_transient, capture, run_cmd
from pipewarden.types import Status, StepResult


def test_missing_binary_required(tmp_path: Path) -> None:
    r = run_cmd(["definitely-not-a-real-binary-xyz"], cwd=tmp_path,
                name="missing", timeout=5, required=True, stream=False)
    assert r.status == Status.FAILED
    assert "not found" in r.message


def test_missing_binary_optional(tmp_path: Path) -> None:
    r = run_cmd(["definitely-not-a-real-binary-xyz"], cwd=tmp_path,
                name="missing", timeout=5, required=False, stream=False)
    assert r.status == Status.WARNED


def test_successful_command(tmp_path: Path) -> None:
    r = run_cmd([sys.executable, "-c", "print('hi')"], cwd=tmp_path,
                name="echo", timeout=10, required=True, stream=False)
    assert r.status == Status.PASSED
    assert r.returncode == 0
    assert "hi" in r.stdout_tail


def test_nonzero_required_fails(tmp_path: Path) -> None:
    r = run_cmd([sys.executable, "-c", "import sys; sys.exit(7)"], cwd=tmp_path,
                name="exit7", timeout=10, required=True, stream=False)
    assert r.status == Status.FAILED
    assert r.returncode == 7


def test_nonzero_optional_warns(tmp_path: Path) -> None:
    r = run_cmd([sys.executable, "-c", "import sys; sys.exit(7)"], cwd=tmp_path,
                name="exit7", timeout=10, required=False, stream=False)
    assert r.status == Status.WARNED


def test_timeout_kills_process(tmp_path: Path) -> None:
    r = run_cmd(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        cwd=tmp_path, name="sleeper", timeout=1, required=True, stream=False,
    )
    assert r.status == Status.FAILED
    assert "timeout" in r.message


def test_capture_returns_stdout(tmp_path: Path) -> None:
    out = capture([sys.executable, "-c", "print('hello')"], cwd=tmp_path)
    assert out is not None and "hello" in out


def test_capture_none_on_failure(tmp_path: Path) -> None:
    out = capture([sys.executable, "-c", "import sys; sys.exit(1)"], cwd=tmp_path)
    assert out is None


# ---------------------------------------------------------------------------
# _is_transient
# ---------------------------------------------------------------------------

def test_is_transient_passed_result() -> None:
    r = StepResult(name="x", status=Status.PASSED)
    assert _is_transient(r) is False


def test_is_transient_failed_with_timeout_message() -> None:
    r = StepResult(name="x", status=Status.FAILED, message="timeout after 60s")
    assert _is_transient(r) is True


def test_is_transient_failed_with_network_in_tail() -> None:
    r = StepResult(name="x", status=Status.FAILED,
                   message="exit 1", stdout_tail="connection reset by peer")
    assert _is_transient(r) is True


def test_is_transient_failed_no_keywords() -> None:
    r = StepResult(name="x", status=Status.FAILED, message="exit 1 — command: npm")
    assert _is_transient(r) is False


# ---------------------------------------------------------------------------
# OSError on spawn
# ---------------------------------------------------------------------------

def test_oserror_on_spawn_required(tmp_path: Path) -> None:
    with patch("pipewarden.runner.subprocess.Popen", side_effect=OSError("permission denied")):
        r = run_cmd([sys.executable, "-c", "pass"], cwd=tmp_path,
                    name="test", timeout=10, required=True, stream=False)
    assert r.status == Status.FAILED
    assert "spawn" in r.message


def test_oserror_on_spawn_optional(tmp_path: Path) -> None:
    with patch("pipewarden.runner.subprocess.Popen", side_effect=OSError("permission denied")):
        r = run_cmd([sys.executable, "-c", "pass"], cwd=tmp_path,
                    name="test", timeout=10, required=False, stream=False)
    assert r.status == Status.WARNED


# ---------------------------------------------------------------------------
# Retry loop
# ---------------------------------------------------------------------------

def test_retry_on_transient_failure(tmp_path: Path) -> None:
    call_count = [0]

    def mock_run_once(*args: object, **kwargs: object) -> StepResult:
        call_count[0] += 1
        if call_count[0] == 1:
            return StepResult(name="test", status=Status.FAILED,
                              message="connection reset by peer")
        return StepResult(name="test", status=Status.PASSED, duration_s=0.1)

    with (patch("pipewarden.runner._run_once", mock_run_once),
          patch("pipewarden.runner.time.sleep")):
        r = run_cmd([sys.executable, "-c", "pass"], cwd=tmp_path,
                    name="test", timeout=10, required=True, stream=False,
                    retries=1, backoff_base=0.001)

    assert r.status == Status.PASSED
    assert call_count[0] == 2
