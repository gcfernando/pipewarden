"""Shared test fixtures."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from collections.abc import Sequence

import pytest

from pipewarden.config import PipelineConfig
from pipewarden.types import Status, StepResult


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """A blank temp directory acting as a project root."""
    return tmp_path


@pytest.fixture
def cfg() -> PipelineConfig:
    """Provide a default PipelineConfig for each test."""
    return PipelineConfig()


class CallRecorder:
    """Replaces run_cmd in stage tests. Records every call and returns scripted results."""

    def __init__(self, default_status: Status = Status.PASSED) -> None:
        """Initialise the recorder with a default status for all calls unless overridden."""
        self.calls: list[dict[str, Any]] = []
        self.default_status = default_status
        self.overrides: dict[str, Status] = {}

    def __call__(
        self,
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
        """Record the call and return a StepResult using the override map or the default status."""
        self.calls.append({"cmd": list(cmd), "name": name, "timeout": timeout,
                           "required": required})
        status = self.overrides.get(name, self.default_status)
        return StepResult(
            name=name,
            status=status,
            duration_s=0.01,
            returncode=0 if status == Status.PASSED else 1,
            message="" if status == Status.PASSED else "mocked failure",
        )

    def cmds(self) -> list[list[str]]:
        """Return just the command lists from all recorded calls."""
        return [c["cmd"] for c in self.calls]

    def names(self) -> list[str]:
        """Return just the step names from all recorded calls."""
        return [c["name"] for c in self.calls]


@pytest.fixture
def recorder() -> CallRecorder:
    """Provide a fresh CallRecorder that defaults to PASSED for each test."""
    return CallRecorder()
