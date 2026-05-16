from pathlib import Path

from pipewarden.config import SecretsConfig
from pipewarden.secrets import SECRET_PATTERNS, _compile_glob, scan_secrets_fallback
from pipewarden.types import Status


def test_clean_repo(tmp_path: Path) -> None:
    (tmp_path / "code.py").write_text("def hello(): return 'world'\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.PASSED
    assert r.findings == []


def test_aws_key_detected(tmp_path: Path) -> None:
    (tmp_path / "leak.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "aws.access_key" for f in r.findings)
    # snippet should be redacted (short) — never the full secret
    assert all(len(f.snippet) <= 20 for f in r.findings)


def test_github_pat_detected(tmp_path: Path) -> None:
    (tmp_path / "creds").write_text("token=ghp_" + "a" * 36 + "\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "github.pat_classic" for f in r.findings)


def test_private_key_detected(tmp_path: Path) -> None:
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----\n"
    )
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED


def test_path_allowlist(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "fake.txt").write_text("AKIAIOSFODNN7EXAMPLE")
    cfg = SecretsConfig(allowlist_paths=["tests/fixtures/*"])
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


def test_rule_allowlist(tmp_path: Path) -> None:
    (tmp_path / "leak.txt").write_text("AKIAIOSFODNN7EXAMPLE")
    cfg = SecretsConfig(allowlist_rules=["aws.access_key"])
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


def test_binary_files_skipped(tmp_path: Path) -> None:
    # An image with what looks like a secret in its bytes — shouldn't be read.
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nAKIAIOSFODNN7EXAMPLE")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.PASSED


def test_large_files_skipped(tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text("AKIAIOSFODNN7EXAMPLE" + "x" * 2_000_000)
    cfg = SecretsConfig(max_file_bytes=1000)
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


def test_findings_include_location(tmp_path: Path) -> None:
    (tmp_path / "leak.py").write_text("# line 1\n# line 2\nKEY='AKIAIOSFODNN7EXAMPLE'\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert any(f.line == 3 for f in r.findings)


def test_all_patterns_compile() -> None:
    # Sanity: regression guard for badly-formed patterns.
    for rule_id, _sev, pattern in SECRET_PATTERNS:
        assert pattern.pattern, rule_id


def test_string_allowlist(tmp_path: Path) -> None:
    (tmp_path / "doc.md").write_text("Example: AKIAIOSFODNN7EXAMPLE\n")
    cfg = SecretsConfig(allowlist_strings=["AKIAIOSFODNN7EXAMPLE"])
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


# ---------------------------------------------------------------------------
# _compile_glob
# ---------------------------------------------------------------------------

def test_compile_glob_double_star_slash_matches_nested() -> None:
    rx = _compile_glob("tests/fixtures/**")
    assert rx.match("tests/fixtures/sub/file.txt") is not None
    assert rx.match("tests/fixtures/file.txt") is not None
    assert rx.match("other/file.txt") is None


def test_compile_glob_double_star_prefix_matches_any_dir() -> None:
    rx = _compile_glob("**/test.py")
    assert rx.match("a/b/test.py") is not None
    assert rx.match("test.py") is not None
    assert rx.match("a/test.txt") is None


def test_compile_glob_double_star_alone_matches_any() -> None:
    rx = _compile_glob("dist/**")
    assert rx.match("dist/sub/file.js") is not None


def test_compile_glob_single_star_no_slash() -> None:
    rx = _compile_glob("src/*.py")
    assert rx.match("src/foo.py") is not None
    assert rx.match("src/sub/foo.py") is None


def test_compile_glob_question_mark() -> None:
    rx = _compile_glob("src/?.py")
    assert rx.match("src/a.py") is not None
    assert rx.match("src/ab.py") is None


def test_path_allowlist_double_star_matches_subdirs(tmp_path: Path) -> None:
    sub = tmp_path / "tests" / "fixtures" / "nested"
    sub.mkdir(parents=True)
    (sub / "fake.txt").write_text("AKIAIOSFODNN7EXAMPLE")
    cfg = SecretsConfig(allowlist_paths=["tests/fixtures/**"])
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


# ---------------------------------------------------------------------------
# New secret patterns
# ---------------------------------------------------------------------------

def test_gitlab_pat_detected(tmp_path: Path) -> None:
    (tmp_path / "creds.txt").write_text("token=glpat-" + "a" * 20 + "\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "gitlab.pat" for f in r.findings)


def test_anthropic_key_detected(tmp_path: Path) -> None:
    (tmp_path / "key.txt").write_text("key=sk-ant-" + "a" * 40 + "\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "anthropic.api_key" for f in r.findings)


def test_sendgrid_key_detected(tmp_path: Path) -> None:
    key = "SG." + "a" * 22 + "." + "b" * 43
    (tmp_path / "config.txt").write_text(f"SENDGRID_API_KEY={key}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "sendgrid.api_key" for f in r.findings)


def test_mongodb_connection_string_detected(tmp_path: Path) -> None:
    (tmp_path / "db.txt").write_text("mongodb://user:pass@host:27017/db\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "mongodb.connection_string" for f in r.findings)
