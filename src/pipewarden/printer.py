"""Console output. The only module that touches stdout directly for humans."""
from __future__ import annotations

import os
import sys

from .types import Report, Status

_ICONS = {
    Status.PASSED:  "✓",
    Status.FAILED:  "✗",
    Status.SKIPPED: "·",
    Status.WARNED:  "⚠",
}

# Respect NO_COLOR (https://no-color.org) and non-TTY by default.
def _supports_color(force: bool = False) -> bool:
    """Return True if the terminal can render ANSI color codes.

    Always returns False when the NO_COLOR environment variable is set,
    which is the standard convention for disabling color in CLI tools.
    """
    if "NO_COLOR" in os.environ:
        return False
    if force:
        return True
    return sys.stdout.isatty()


class Printer:
    """Writes human-readable console output with optional ANSI color."""

    def __init__(self, quiet: bool = False, color: bool = True) -> None:
        """Create a Printer. Pass quiet=True to suppress all non-error output."""
        self.quiet = quiet
        self.color = color and _supports_color()

    def _c(self, code: str, text: str) -> str:
        """Wrap text in an ANSI escape sequence, or return it unchanged if color is off."""
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def section(self, title: str) -> None:
        """Print a bold section header — the separator line before each language stage."""
        if self.quiet:
            return
        bar = "═" * 64
        print(f"\n{self._c('1;36', bar)}")
        print(self._c("1;36", f"  {title}"))
        print(self._c("1;36", bar))

    def info(self, msg: str) -> None:
        """Print an indented informational line (e.g. root path, detected languages)."""
        if not self.quiet:
            print(f"  {msg}")

    def ok(self, msg: str) -> None:
        """Print a green check-mark line for a passing step."""
        if not self.quiet:
            print(self._c("1;32", f"✓ {msg}"))

    def warn(self, msg: str) -> None:
        """Print a yellow warning line for a non-blocking issue."""
        if not self.quiet:
            print(self._c("1;33", f"⚠ {msg}"))

    def fail(self, msg: str) -> None:
        """Print a red failure line to stderr — always shown, even in quiet mode."""
        print(self._c("1;31", f"✗ {msg}"), file=sys.stderr)


def print_summary(report: Report, printer: Printer) -> None:
    """Print the final summary table and, if there were failures, the output tails."""
    printer.section("Summary")
    if not report.steps:
        printer.info("nothing to do")
        return

    width = max(len(s.name) for s in report.steps)
    for s in report.steps:
        icon = _ICONS[s.status]
        line = (f"  {icon} {s.name.ljust(width)}  "
                f"{s.status.value:<8} {s.duration_s:>6.1f}s")
        if s.message:
            line += f"   {s.message}"
        print(line)

    fails = report.failed()
    print()
    if fails:
        passed = sum(1 for s in report.steps if s.status == Status.PASSED)
        warned = sum(1 for s in report.steps if s.status == Status.WARNED)
        skipped = sum(1 for s in report.steps if s.status == Status.SKIPPED)
        printer.fail(
            f"{len(fails)} failed, {passed} passed, "
            f"{warned} warned, {skipped} skipped — total {report.duration_s:.1f}s"
        )
        print("\nFailing step output (tail):", file=sys.stderr)
        for s in fails:
            print(f"\n── {s.name} ──", file=sys.stderr)
            print(s.stdout_tail or "(no output captured)", file=sys.stderr)
        findings = report.all_findings()
        if findings:
            print(f"\nFindings ({len(findings)}):", file=sys.stderr)
            for f in findings[:50]:
                print(f"  {f.severity.value:<8} {f.file}:{f.line}  "
                      f"[{f.rule_id}]  {f.snippet}", file=sys.stderr)
            if len(findings) > 50:
                print(f"  … and {len(findings) - 50} more", file=sys.stderr)
    else:
        printer.ok(f"all {len(report.steps)} steps passed "
                   f"in {report.duration_s:.1f}s")
