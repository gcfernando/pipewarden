"""Subprocess execution. The ONLY place we spawn processes.

Centralising this lets us guarantee timeouts, output capture, retries, and a
uniform StepResult for every command.
"""

from __future__ import annotations

import contextlib
import os
import select
import shutil
import subprocess
import sys
import time
from collections import deque
from collections.abc import Sequence
from pathlib import Path

from .types import Status, StepResult

_POSIX = sys.platform != "win32"

# Lines captured per step for the failure tail.
TAIL_LINES = 60

# Exit codes that indicate a transient failure worth retrying (network/timeout).
_TRANSIENT_RETURNCODES: frozenset[int] = frozenset({
    1,    # generic; refined by message heuristics below
    124,  # timeout (GNU coreutils timeout command)
    137,  # SIGKILL (OOM or timeout)
    143,  # SIGTERM
})

_TRANSIENT_MESSAGES = (
    "timeout", "timed out", "connection reset", "network", "ssl", "certificate",
    "temporary failure", "name or service not known", "rate limit", "503", "502",
    "could not resolve", "eof occurred", "broken pipe",
)


def _is_transient(result: StepResult) -> bool:
    """Heuristic: did this failure look like a transient network/resource issue?"""
    if result.status != Status.FAILED:
        return False
    msg = (result.message or "").lower()
    tail = (result.stdout_tail or "").lower()
    return any(t in msg or t in tail for t in _TRANSIENT_MESSAGES)


def run_cmd(
    cmd: Sequence[str],
    *,
    cwd: Path,
    name: str,
    timeout: int,
    env: dict[str, str] | None = None,
    required: bool = True,
    stream: bool = True,
    indent: str = "   ",
    retries: int = 0,
    backoff_base: float = 2.0,
) -> StepResult:
    """Run `cmd`, stream output, capture tail, return StepResult.

    `required=False`  downgrades failures to WARNED.
    `retries`         how many additional attempts on transient failures.
    `backoff_base`    seconds before first retry; doubles each attempt.
    """
    attempt = 0
    wait = backoff_base
    while True:
        result = _run_once(cmd, cwd=cwd, name=name, timeout=timeout,
                           env=env, required=required, stream=stream, indent=indent)
        if retries > 0 and attempt < retries and _is_transient(result):
            attempt += 1
            suffix = f" (retry {attempt}/{retries} in {wait:.0f}s)"
            print(f"   ⟳ {name}{suffix}", flush=True)
            time.sleep(wait)
            wait *= 2
            continue
        return result


def _run_once(
    cmd: Sequence[str],
    *,
    cwd: Path,
    name: str,
    timeout: int,
    env: dict[str, str] | None = None,
    required: bool = True,
    stream: bool = True,
    indent: str = "   ",
) -> StepResult:
    """Execute cmd once and return the result. Called by run_cmd for each attempt."""
    start = time.monotonic()
    binary = shutil.which(cmd[0])
    if binary is None:
        return StepResult(
            name=name,
            status=Status.FAILED if required else Status.WARNED,
            message=f"command not found: {cmd[0]}",
        )

    full_env = {**os.environ, **(env or {})}

    try:
        proc = subprocess.Popen(
            list(cmd),
            cwd=str(cwd),
            env=full_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as e:
        return StepResult(
            name=name,
            status=Status.FAILED if required else Status.WARNED,
            message=f"failed to spawn: {e}",
        )

    # Use deque for O(1) append+trim instead of O(n) list slicing.
    tail: deque[str] = deque(maxlen=TAIL_LINES * 4)
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout

    try:
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=5)
                    with contextlib.suppress(Exception):
                        for line in proc.stdout:
                            tail.append(line.rstrip("\n"))
                            if stream:
                                print(f"{indent}{line}", end="")
                    return StepResult(
                        name=name,
                        status=Status.FAILED if required else Status.WARNED,
                        duration_s=time.monotonic() - start,
                        message=f"timeout after {timeout}s — command: {cmd[0]}",
                        stdout_tail="\n".join(list(tail)[-TAIL_LINES:]),
                    )

                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=min(0.1, remaining))

                while True:
                    if _POSIX:
                        readable, _, _ = select.select([proc.stdout], [], [], 0.0)
                        if not readable:
                            break
                    line = proc.stdout.readline()
                    if not line:
                        break
                    tail.append(line.rstrip("\n"))
                    if stream:
                        print(f"{indent}{line}", end="")

                if proc.poll() is not None:
                    break

            returncode = proc.wait()
        finally:
            with contextlib.suppress(Exception):
                proc.stdout.close()
    except KeyboardInterrupt:  # pragma: no cover
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        raise

    duration = time.monotonic() - start
    tail_str = "\n".join(list(tail)[-TAIL_LINES:])

    if returncode == 0:
        return StepResult(
            name=name, status=Status.PASSED,
            duration_s=duration, returncode=0, stdout_tail=tail_str,
        )
    return StepResult(
        name=name,
        status=Status.FAILED if required else Status.WARNED,
        duration_s=duration,
        returncode=returncode,
        message=f"exit {returncode} — command: {cmd[0]}",
        stdout_tail=tail_str,
    )


def capture(cmd: Sequence[str], cwd: Path, timeout: int = 30) -> str | None:
    """Run a command silently and return stdout, or None on any failure."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        return subprocess.check_output(
            list(cmd), cwd=str(cwd), text=True,
            timeout=timeout, stderr=subprocess.DEVNULL,
        )
    except (subprocess.SubprocessError, OSError):
        return None
