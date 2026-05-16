"""Report serializers. Pure functions: take a Report, produce a string/dict."""
from __future__ import annotations

import hashlib
import json
from typing import Any
from xml.etree import ElementTree as ET

from .types import Report, Severity, Status

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


# ---------------------------------------------------------------------------
# SARIF 2.1.0 — consumed by GitHub Code Scanning, Azure DevOps, etc.
# Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}


def _fingerprint(rule_id: str, file: str, line: int) -> str:
    """SHA-256 fingerprint used by GitHub Code Scanning to deduplicate findings."""
    return hashlib.sha256(f"{rule_id}|{file}|{line}".encode()).hexdigest()


def to_sarif(report: Report) -> str:
    """Emit a SARIF document covering all findings across steps."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for step in report.steps:
        for f in step.findings:
            rules.setdefault(f.rule_id, {
                "id": f.rule_id,
                "shortDescription": {"text": f.rule_id},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "warning")},
            })
            results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "fingerprints": {
                    "primaryLocationLineHash/v1": _fingerprint(f.rule_id, f.file, f.line),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {
                            "startLine": max(f.line, 1),
                            "startColumn": max(f.column, 1),
                            "snippet": {"text": f.snippet} if f.snippet else {},
                        },
                    },
                }],
            })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pipewarden",
                    "version": report.tool_version,
                    "informationUri": "https://github.com/gcfernando/pipewarden",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


# ---------------------------------------------------------------------------
# JUnit XML — every CI on earth knows how to render this.
# ---------------------------------------------------------------------------

def to_junit_xml(report: Report) -> str:
    """Map each step to a <testcase>; failures attach the stdout tail."""
    total = len(report.steps)
    failures = sum(1 for s in report.steps if s.status == Status.FAILED)
    skipped  = sum(1 for s in report.steps if s.status == Status.SKIPPED)
    suite_time = f"{report.duration_s:.3f}"

    testsuites = ET.Element("testsuites", {
        "name": "pipewarden",
        "tests": str(total),
        "failures": str(failures),
        "skipped": str(skipped),
        "time": suite_time,
    })
    testsuite = ET.SubElement(testsuites, "testsuite", {
        "name": "pipewarden",
        "tests": str(total),
        "failures": str(failures),
        "skipped": str(skipped),
        "time": suite_time,
    })

    for s in report.steps:
        case = ET.SubElement(testsuite, "testcase", {
            "classname": "pipewarden",
            "name": s.name,
            "time": f"{s.duration_s:.3f}",
        })
        if s.status == Status.FAILED:
            fail = ET.SubElement(case, "failure", {
                "message": s.message or "step failed",
                "type": "PipewarnedFailure",
            })
            fail.text = s.stdout_tail or s.message
        elif s.status == Status.SKIPPED:
            ET.SubElement(case, "skipped", {"message": s.message or "skipped"})
        elif s.status == Status.WARNED:
            # JUnit has no "warned" — represent as system-out.
            sysout = ET.SubElement(case, "system-out")
            sysout.text = f"WARNED: {s.message}\n{s.stdout_tail}"

    # ET.tostring returns bytes by default; we want a string.
    return ET.tostring(testsuites, encoding="unicode")


# ---------------------------------------------------------------------------
# GitHub Actions annotations — printed to stdout, picked up by the runner.
# Format: ::error file={f},line={l},col={c},title={t}::{message}
# ---------------------------------------------------------------------------

def to_github_annotations(report: Report) -> str:
    """Return GitHub Actions workflow commands for every finding.

    Print the result to stdout during a workflow step and GitHub will surface
    inline annotations on the PR diff.
    """
    lines: list[str] = []
    for step in report.steps:
        for f in step.findings:
            level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
            # Encode special characters per the GHA annotation spec.
            msg = (f.message
                   .replace("%", "%25")
                   .replace("\r", "%0D")
                   .replace("\n", "%0A")
                   .replace(":", "%3A")
                   .replace(",", "%2C"))
            lines.append(
                f"::{level} file={f.file},line={f.line},"
                f"col={f.column},title={f.rule_id}::{msg}"
            )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Markdown summary — for $GITHUB_STEP_SUMMARY or local --markdown-out.
# ---------------------------------------------------------------------------

_STATUS_ICON = {
    Status.PASSED:  "✅",
    Status.FAILED:  "❌",
    Status.WARNED:  "⚠️",
    Status.SKIPPED: "⏭️",
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}

# Max findings rows to include before truncating (keeps summary under GHA 1 MiB limit).
_MAX_FINDING_ROWS = 100


def to_markdown_summary(report: Report) -> str:
    """Produce a Markdown summary suitable for $GITHUB_STEP_SUMMARY or a file."""
    has_failures = any(s.status == Status.FAILED for s in report.steps)
    header_icon = "❌" if has_failures else "✅"

    lines: list[str] = [
        f"## {header_icon} Pipewarden {report.tool_version}",
        "",
        f"**Root:** `{report.root}`  **Duration:** {report.duration_s:.1f}s",
        "",
        "| Stage | Status | Duration | Details |",
        "|-------|--------|----------|---------|",
    ]

    for s in report.steps:
        icon = _STATUS_ICON.get(s.status, "•")
        msg = (s.message or "").replace("|", "\\|")
        dur = f"{s.duration_s:.1f}s" if s.duration_s else "—"
        lines.append(f"| `{s.name}` | {icon} {s.status.name} | {dur} | {msg} |")

    # Findings table
    all_findings = [f for s in report.steps for f in s.findings]
    if all_findings:
        truncated = len(all_findings) > _MAX_FINDING_ROWS
        shown = all_findings[:_MAX_FINDING_ROWS]
        lines += [
            "",
            "### Findings",
            "",
            "| Severity | Rule | File | Line | Message |",
            "|----------|------|------|------|---------|",
        ]
        for f in shown:
            sev_icon = _SEVERITY_ICON.get(f.severity, "")
            file_col = f.file.replace("|", "\\|")
            msg_col = f.message.replace("|", "\\|")
            lines.append(
                f"| {sev_icon} {f.severity.name} | `{f.rule_id}` "
                f"| `{file_col}` | {f.line} | {msg_col} |"
            )
        if truncated:
            lines.append(
                f"\n> ⚠️ Showing {_MAX_FINDING_ROWS} of {len(all_findings)} findings. "
                "Use `--sarif-out` to export the full list."
            )

    lines.append("")
    return "\n".join(lines)
