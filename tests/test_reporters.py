"""Tests for report serializers — JSON, SARIF, JUnit XML, GitHub Annotations, and Markdown."""
import json
from xml.etree import ElementTree as ET

from pipewarden.reporters import (
    to_github_annotations,
    to_json,
    to_junit_xml,
    to_markdown_summary,
    to_sarif,
)
from pipewarden.types import Finding, Report, Severity, Status, StepResult


def _sample_report() -> Report:
    """Build a representative report with passed, failed, skipped, and secret-finding steps."""
    r = Report(root="/repo", tool_version="9.9.9")
    r.add(StepResult(name="py:lint", status=Status.PASSED, duration_s=1.2))
    r.add(StepResult(name="py:test", status=Status.FAILED, duration_s=3.4,
                     returncode=1, message="exit 1", stdout_tail="boom"))
    r.add(StepResult(name="docker:build", status=Status.SKIPPED,
                     message="no docker"))
    r.add(StepResult(name="secrets:fallback", status=Status.FAILED,
                     duration_s=0.1, message="1 finding",
                     findings=[Finding(
                         rule_id="aws.access_key", message="possible aws.access_key",
                         severity=Severity.CRITICAL,
                         file="src/x.py", line=10, column=5, snippet="AKIA…MPLE",
                     )]))
    r.duration_s = 4.7
    return r


def test_json_round_trip() -> None:
    """to_json should produce valid JSON with correct summary counts and step names."""
    rep = _sample_report()
    data = json.loads(to_json(rep))
    assert data["tool_version"] == "9.9.9"
    assert data["summary"]["total"] == 4
    assert data["summary"]["failed"] == 2
    assert data["summary"]["findings"] == 1
    names = [s["name"] for s in data["steps"]]
    assert "py:test" in names


def test_sarif_well_formed() -> None:
    """SARIF output should be valid 2.1.0 with the finding mapped to a result and location."""
    rep = _sample_report()
    data = json.loads(to_sarif(rep))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "pipewarden"
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "aws.access_key"
    assert results[0]["level"] == "error"
    loc = results[0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/x.py"
    assert loc["region"]["startLine"] == 10


def test_junit_parses_as_xml() -> None:
    """JUnit XML should be well-formed and contain the right test/failure/skip counts."""
    rep = _sample_report()
    xml = to_junit_xml(rep)
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.attrib["tests"] == "4"
    assert suite.attrib["failures"] == "2"
    failure_cases = [c for c in suite.findall("testcase") if c.find("failure") is not None]
    assert len(failure_cases) == 2
    skipped_cases = [c for c in suite.findall("testcase") if c.find("skipped") is not None]
    assert len(skipped_cases) == 1


def test_sarif_empty_report() -> None:
    """A report with no findings should produce a SARIF document with an empty results list."""
    rep = Report(root="/r", tool_version="1.0")
    data = json.loads(to_sarif(rep))
    assert data["runs"][0]["results"] == []


def test_sarif_has_fingerprint() -> None:
    """Each SARIF result should include a 64-character SHA-256 fingerprint for deduplication."""
    rep = _sample_report()
    data = json.loads(to_sarif(rep))
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert "primaryLocationLineHash/v1" in results[0]["fingerprints"]
    assert len(results[0]["fingerprints"]["primaryLocationLineHash/v1"]) == 64


def test_github_annotations_with_finding() -> None:
    """A CRITICAL finding should produce a ::error annotation with the correct file and line."""
    rep = _sample_report()
    out = to_github_annotations(rep)
    assert "::error file=src/x.py,line=10" in out
    assert "aws.access_key" in out


def test_github_annotations_empty_report() -> None:
    """A report with no findings should produce an empty string, not a blank line."""
    rep = Report(root="/r", tool_version="1.0")
    out = to_github_annotations(rep)
    assert out == ""


def test_github_annotations_low_severity() -> None:
    """LOW severity findings should produce ::warning annotations, not ::error."""
    rep = Report(root="/r", tool_version="1.0")
    rep.add(StepResult(name="s", status=Status.FAILED, findings=[
        Finding(rule_id="test.rule", message="low severity finding",
                severity=Severity.LOW, file="a.py", line=1, column=1),
    ]))
    out = to_github_annotations(rep)
    assert "::warning " in out
    assert "::error" not in out


def test_github_annotations_encodes_special_chars() -> None:
    """Colons, commas, and newlines in messages should be percent-encoded per the GHA spec."""
    rep = Report(root="/r", tool_version="1.0")
    rep.add(StepResult(name="s", status=Status.FAILED, findings=[
        Finding(rule_id="r", message="msg: with,commas\nand newlines",
                severity=Severity.HIGH, file="f.py", line=1, column=1),
    ]))
    out = to_github_annotations(rep)
    assert "%3A" in out or "%0A" in out or "%2C" in out


def test_markdown_summary_all_pass() -> None:
    """A fully-passing report should render with a green ✅ header and list the step name."""
    rep = Report(root="/repo", tool_version="1.0")
    rep.add(StepResult(name="py:lint", status=Status.PASSED, duration_s=1.0))
    rep.duration_s = 1.0
    out = to_markdown_summary(rep)
    assert "Pipewarden" in out
    assert "✅" in out
    assert "py:lint" in out


def test_markdown_summary_with_failures() -> None:
    """A report with a failed step should render with a red ❌ header."""
    rep = Report(root="/repo", tool_version="1.0")
    rep.add(StepResult(name="py:test", status=Status.FAILED, duration_s=2.0, message="boom"))
    rep.duration_s = 2.0
    out = to_markdown_summary(rep)
    assert "❌" in out


def test_markdown_summary_with_findings() -> None:
    """When there are findings, a Findings table should appear with the rule ID and file path."""
    rep = _sample_report()
    out = to_markdown_summary(rep)
    assert "### Findings" in out
    assert "aws.access_key" in out
    assert "src/x.py" in out


def test_markdown_summary_skipped_step() -> None:
    """A skipped step should appear in the summary table with SKIPPED status text."""
    rep = Report(root="/r", tool_version="1.0")
    rep.add(StepResult(name="docker:build", status=Status.SKIPPED, message="no docker"))
    out = to_markdown_summary(rep)
    assert "SKIPPED" in out


def test_junit_warned_step() -> None:
    """A WARNED step should be represented as a system-out element in the JUnit XML."""
    rep = Report(root="/r", tool_version="1.0")
    rep.add(StepResult(name="docker:build", status=Status.WARNED, message="daemon missing"))
    xml = to_junit_xml(rep)
    assert "system-out" in xml
    assert "WARNED" in xml
