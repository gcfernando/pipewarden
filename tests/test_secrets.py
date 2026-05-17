"""Tests for the secret scanner — pattern detection, allowlists, gitleaks dispatch, and glob compilation."""
from pathlib import Path
from unittest.mock import patch

from pipewarden.config import SecretsConfig
from pipewarden.secrets import SECRET_PATTERNS, _compile_glob, scan_secrets, scan_secrets_fallback
from pipewarden.types import Status, StepResult


def test_clean_repo(tmp_path: Path) -> None:
    """A file with no credentials should pass with an empty findings list."""
    (tmp_path / "code.py").write_text("def hello(): return 'world'\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.PASSED
    assert r.findings == []


def test_aws_key_detected(tmp_path: Path) -> None:
    """An AWS access key should be detected and the snippet should be redacted (≤20 chars)."""
    (tmp_path / "leak.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "aws.access_key" for f in r.findings)
    assert all(len(f.snippet) <= 20 for f in r.findings)


def test_github_pat_detected(tmp_path: Path) -> None:
    """A classic GitHub PAT (ghp_ prefix) should be detected as github.pat_classic."""
    (tmp_path / "creds").write_text("token=ghp_" + "a" * 36 + "\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "github.pat_classic" for f in r.findings)


def test_private_key_detected(tmp_path: Path) -> None:
    """A PEM private key block should be detected as a secret."""
    (tmp_path / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----\n"
    )
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED


def test_path_allowlist(tmp_path: Path) -> None:
    """A file matched by allowlist_paths should be excluded from scanning."""
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "fake.txt").write_text("AKIAIOSFODNN7EXAMPLE")
    cfg = SecretsConfig(allowlist_paths=["tests/fixtures/*"])
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


def test_rule_allowlist(tmp_path: Path) -> None:
    """A rule ID in allowlist_rules should suppress findings from that pattern."""
    (tmp_path / "leak.txt").write_text("AKIAIOSFODNN7EXAMPLE")
    cfg = SecretsConfig(allowlist_rules=["aws.access_key"])
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


def test_binary_files_skipped(tmp_path: Path) -> None:
    """Binary files (detected by null bytes or magic headers) should not be scanned."""
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\nAKIAIOSFODNN7EXAMPLE")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.PASSED


def test_large_files_skipped(tmp_path: Path) -> None:
    """Files exceeding max_file_bytes should be skipped entirely."""
    big = tmp_path / "big.txt"
    big.write_text("AKIAIOSFODNN7EXAMPLE" + "x" * 2_000_000)
    cfg = SecretsConfig(max_file_bytes=1000)
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


def test_findings_include_location(tmp_path: Path) -> None:
    """The reported line number should correctly point to the line containing the secret."""
    (tmp_path / "leak.py").write_text("# line 1\n# line 2\nKEY='AKIAIOSFODNN7EXAMPLE'\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert any(f.line == 3 for f in r.findings)


def test_all_patterns_compile() -> None:
    """Every pattern in SECRET_PATTERNS should be a compiled regex with a non-empty pattern string."""
    for rule_id, _sev, pattern in SECRET_PATTERNS:
        assert pattern.pattern, rule_id


def test_string_allowlist(tmp_path: Path) -> None:
    """A string in allowlist_strings should suppress any finding whose snippet matches it."""
    (tmp_path / "doc.md").write_text("Example: AKIAIOSFODNN7EXAMPLE\n")
    cfg = SecretsConfig(allowlist_strings=["AKIAIOSFODNN7EXAMPLE"])
    r = scan_secrets_fallback(tmp_path, cfg)
    assert r.status == Status.PASSED


# ---------------------------------------------------------------------------
# _compile_glob
# ---------------------------------------------------------------------------

def test_compile_glob_double_star_slash_matches_nested() -> None:
    """A pattern ending with /** should match files at any depth below the prefix."""
    rx = _compile_glob("tests/fixtures/**")
    assert rx.match("tests/fixtures/sub/file.txt") is not None
    assert rx.match("tests/fixtures/file.txt") is not None
    assert rx.match("other/file.txt") is None


def test_compile_glob_double_star_prefix_matches_any_dir() -> None:
    """A pattern starting with **/ should match the filename under any directory prefix."""
    rx = _compile_glob("**/test.py")
    assert rx.match("a/b/test.py") is not None
    assert rx.match("test.py") is not None
    assert rx.match("a/test.txt") is None


def test_compile_glob_double_star_alone_matches_any() -> None:
    """prefix/** should match any path that starts with the prefix."""
    rx = _compile_glob("dist/**")
    assert rx.match("dist/sub/file.js") is not None


def test_compile_glob_single_star_no_slash() -> None:
    """A single * should match any filename but not cross a directory separator."""
    rx = _compile_glob("src/*.py")
    assert rx.match("src/foo.py") is not None
    assert rx.match("src/sub/foo.py") is None


def test_compile_glob_question_mark() -> None:
    """A ? should match exactly one character."""
    rx = _compile_glob("src/?.py")
    assert rx.match("src/a.py") is not None
    assert rx.match("src/ab.py") is None


def test_path_allowlist_double_star_matches_subdirs(tmp_path: Path) -> None:
    """An allowlist pattern with ** should suppress files in deeply nested subdirectories."""
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
    """A GitLab PAT (glpat- prefix) should be detected as gitlab.pat."""
    (tmp_path / "creds.txt").write_text("token=glpat-" + "a" * 20 + "\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "gitlab.pat" for f in r.findings)


def test_anthropic_key_detected(tmp_path: Path) -> None:
    """An Anthropic API key (sk-ant- prefix) should be detected as anthropic.api_key."""
    (tmp_path / "key.txt").write_text("key=sk-ant-" + "a" * 40 + "\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "anthropic.api_key" for f in r.findings)


def test_sendgrid_key_detected(tmp_path: Path) -> None:
    """A SendGrid API key (SG. prefix) should be detected as sendgrid.api_key."""
    key = "SG." + "a" * 22 + "." + "b" * 43
    (tmp_path / "config.txt").write_text(f"SENDGRID_API_KEY={key}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "sendgrid.api_key" for f in r.findings)


def test_mongodb_connection_string_detected(tmp_path: Path) -> None:
    """A mongodb:// URI with embedded credentials should be detected."""
    (tmp_path / "db.txt").write_text("mongodb://user:pass@host:27017/db\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "mongodb.connection_string" for f in r.findings)


# ---------------------------------------------------------------------------
# Database URI connection strings
# ---------------------------------------------------------------------------

def test_postgres_connection_string_detected(tmp_path: Path) -> None:
    """A postgresql:// URI with embedded credentials should be detected."""
    (tmp_path / "db.py").write_text('DSN = "postgresql://admin:s3cr3t@db.example.com/prod"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "postgres.connection_string" for f in r.findings)


def test_mysql_connection_string_detected(tmp_path: Path) -> None:
    """A mysql:// URI with embedded credentials should be detected."""
    (tmp_path / "db.py").write_text('URL = "mysql://root:p@ssword@127.0.0.1/mydb"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "mysql.connection_string" for f in r.findings)


def test_redis_connection_string_with_password_detected(tmp_path: Path) -> None:
    """A redis:// URI with a password in the authority should be detected."""
    (tmp_path / "cache.py").write_text('REDIS_URL = "redis://:supersecret@redis.host:6379/0"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "redis.connection_string" for f in r.findings)


def test_redis_url_without_password_not_detected(tmp_path: Path) -> None:
    """A redis:// URI with no credentials should not be flagged as a secret."""
    (tmp_path / "cache.py").write_text('REDIS_URL = "redis://localhost:6379"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert not any(f.rule_id == "redis.connection_string" for f in r.findings)


def test_amqp_connection_string_detected(tmp_path: Path) -> None:
    """An amqp:// URI with embedded credentials should be detected."""
    (tmp_path / "mq.py").write_text('URL = "amqp://guest:guest123@rabbitmq.host/vhost"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "amqp.connection_string" for f in r.findings)


def test_mssql_connection_string_detected(tmp_path: Path) -> None:
    """An ADO.NET connection string with Password= should be detected as an MSSQL secret."""
    conn = "Server=myserver.database.windows.net;Database=mydb;User Id=admin;Password=Secr3t!;\n"
    (tmp_path / "app.config").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "mssql.connection_string" for f in r.findings)


def test_mssql_integrated_security_not_detected(tmp_path: Path) -> None:
    """An ADO.NET connection string using Integrated Security (no password) should not be flagged."""
    conn = "Server=myserver;Database=mydb;Integrated Security=SSPI;\n"
    (tmp_path / "app.config").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert not any(f.rule_id == "mssql.connection_string" for f in r.findings)


def test_jdbc_connection_string_detected(tmp_path: Path) -> None:
    """A JDBC URL with a password query parameter should be detected."""
    url = 'jdbc:postgresql://db.host:5432/prod?user=admin&password=s3cretPass\n'
    (tmp_path / "datasource.properties").write_text(url)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "jdbc.connection_string" for f in r.findings)


def test_jdbc_sqlserver_semicolon_params_detected(tmp_path: Path) -> None:
    """A JDBC SQL Server URL with semicolon-separated password= should be detected."""
    url = "jdbc:sqlserver://host:1433;databaseName=mydb;user=sa;password=P@ssw0rd\n"
    (tmp_path / "db.props").write_text(url)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "jdbc.connection_string" for f in r.findings)


# ---------------------------------------------------------------------------
# Azure connection strings
# ---------------------------------------------------------------------------

def test_azure_storage_connection_string_detected(tmp_path: Path) -> None:
    """An Azure Blob Storage connection string with AccountKey= should be detected."""
    key = "A" * 43 + "="
    conn = f"DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey={key};\n"
    (tmp_path / "appsettings.json").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "azure.storage_connection_string" for f in r.findings)


def test_azure_cosmos_connection_string_detected(tmp_path: Path) -> None:
    """An Azure Cosmos DB connection string with AccountKey= should be detected."""
    key = "B" * 43 + "="
    conn = f"AccountEndpoint=https://myaccount.documents.azure.com:443/;AccountKey={key};\n"
    (tmp_path / "cosmos.txt").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "azure.cosmos_connection_string" for f in r.findings)


def test_azure_servicebus_connection_string_detected(tmp_path: Path) -> None:
    """An Azure Service Bus connection string with SharedAccessKey= should be detected."""
    key = "C" * 40 + "="
    conn = (
        f"Endpoint=sb://mynamespace.servicebus.windows.net/;"
        f"SharedAccessKeyName=RootManageSharedAccessKey;"
        f"SharedAccessKey={key}\n"
    )
    (tmp_path / "servicebus.txt").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "azure.servicebus_connection_string" for f in r.findings)


# ---------------------------------------------------------------------------
# AWS STS / temporary credentials
# ---------------------------------------------------------------------------

def test_aws_sts_key_detected(tmp_path: Path) -> None:
    """An AWS STS temporary key (ASIA prefix) should be detected as aws.sts_key."""
    (tmp_path / "env.txt").write_text("AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "aws.sts_key" for f in r.findings)


# ---------------------------------------------------------------------------
# Developer platform tokens
# ---------------------------------------------------------------------------

def test_digitalocean_token_detected(tmp_path: Path) -> None:
    """A DigitalOcean personal access token (dop_v1_ prefix) should be detected."""
    token = "dop_v1_" + "a" * 64
    (tmp_path / "tf.tf").write_text(f'token = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "digitalocean.token" for f in r.findings)


def test_github_actions_token_detected(tmp_path: Path) -> None:
    """A GitHub Actions token (ghs_ prefix) should be detected as github.actions_token."""
    token = "ghs_" + "A" * 36
    (tmp_path / "script.sh").write_text(f"TOKEN={token}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "github.actions_token" for f in r.findings)


def test_github_user_token_detected(tmp_path: Path) -> None:
    """A GitHub user-to-server token (ghu_ prefix) should be detected as github.user_token."""
    token = "ghu_" + "B" * 36
    (tmp_path / "script.sh").write_text(f"TOKEN={token}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "github.user_token" for f in r.findings)


def test_linear_api_key_detected(tmp_path: Path) -> None:
    """A Linear API key (lin_api_ prefix) should be detected."""
    token = "lin_api_" + "x" * 40
    (tmp_path / "linear.py").write_text(f'API_KEY = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "linear.api_key" for f in r.findings)


def test_okta_token_detected(tmp_path: Path) -> None:
    """An Okta API token (SSWS prefix) should be detected as okta.token."""
    token = "SSWS " + "A" * 42
    (tmp_path / "okta.py").write_text(f'AUTH = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "okta.token" for f in r.findings)


# ---------------------------------------------------------------------------
# AI / ML platform tokens
# ---------------------------------------------------------------------------

def test_huggingface_token_detected(tmp_path: Path) -> None:
    """A Hugging Face access token (hf_ prefix) should be detected."""
    token = "hf_" + "A" * 34
    (tmp_path / "model.py").write_text(f'HF_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "huggingface.token" for f in r.findings)


def test_replicate_token_detected(tmp_path: Path) -> None:
    """A Replicate API token (r8_ prefix) should be detected."""
    token = "r8_" + "A" * 37
    (tmp_path / "gen.py").write_text(f'TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "replicate.token" for f in r.findings)


# ---------------------------------------------------------------------------
# Communication tokens
# ---------------------------------------------------------------------------

def test_telegram_bot_token_detected(tmp_path: Path) -> None:
    """A Telegram bot token (numeric ID followed by colon and base64 string) should be detected."""
    token = "123456789:AA" + "B" * 33
    (tmp_path / "bot.py").write_text(f'BOT_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "telegram.bot_token" for f in r.findings)


# ---------------------------------------------------------------------------
# Payment — additional
# ---------------------------------------------------------------------------

def test_stripe_test_key_detected(tmp_path: Path) -> None:
    """A Stripe test secret key (sk_test_ prefix) should be detected."""
    token = "sk_test_" + "a" * 24
    (tmp_path / "pay.py").write_text(f'STRIPE_KEY = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "stripe.test_key" for f in r.findings)


def test_stripe_webhook_secret_detected(tmp_path: Path) -> None:
    """A Stripe webhook signing secret (whsec_ prefix) should be detected."""
    token = "whsec_" + "a" * 32
    (tmp_path / "webhook.py").write_text(f'SECRET = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "stripe.webhook_secret" for f in r.findings)


# ---------------------------------------------------------------------------
# E-commerce
# ---------------------------------------------------------------------------

def test_shopify_access_token_detected(tmp_path: Path) -> None:
    """A Shopify Admin API access token (shpat_ prefix) should be detected."""
    token = "shpat_" + "a" * 32
    (tmp_path / "shop.py").write_text(f'ACCESS_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "shopify.access_token" for f in r.findings)


def test_shopify_storefront_token_detected(tmp_path: Path) -> None:
    """A Shopify Storefront API token (shpss_ prefix) should be detected."""
    token = "shpss_" + "b" * 32
    (tmp_path / "shop.py").write_text(f'SF_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "shopify.storefront_token" for f in r.findings)


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

def test_newrelic_license_key_detected(tmp_path: Path) -> None:
    """A New Relic license key (NRAK- prefix) should be detected."""
    key = "NRAK-" + "A" * 32
    (tmp_path / "newrelic.ini").write_text(f"license_key = {key}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "newrelic.license_key" for f in r.findings)


# ---------------------------------------------------------------------------
# scan_secrets — gitleaks dispatch (working tree, history, diff, fallback)
# ---------------------------------------------------------------------------

def test_scan_secrets_uses_gitleaks_when_available(tmp_path: Path) -> None:
    """When gitleaks is on PATH and prefer_external=True, scan_secrets should invoke gitleaks."""
    cfg = SecretsConfig(prefer_external=True)
    fake_result = StepResult(name="secrets:gitleaks", status=Status.PASSED)
    with patch("pipewarden.secrets.shutil.which", return_value="gitleaks"), \
         patch("pipewarden.secrets.run_cmd", return_value=fake_result) as mock_run:
        r = scan_secrets(tmp_path, cfg, timeout=30)
    assert r.name == "secrets:gitleaks"
    called_cmd = mock_run.call_args[0][0]
    assert "--source" in called_cmd


def test_scan_secrets_history_mode_omits_source(tmp_path: Path) -> None:
    """With scan_history=True, gitleaks should be called without --source to scan all commits."""
    cfg = SecretsConfig(prefer_external=True, scan_history=True)
    fake_result = StepResult(name="secrets:gitleaks(history)", status=Status.PASSED)
    with patch("pipewarden.secrets.shutil.which", return_value="gitleaks"), \
         patch("pipewarden.secrets.run_cmd", return_value=fake_result) as mock_run:
        r = scan_secrets(tmp_path, cfg, timeout=30)
    assert r.name == "secrets:gitleaks(history)"
    called_cmd = mock_run.call_args[0][0]
    assert "--source" not in called_cmd


def test_scan_secrets_diff_base_bypasses_gitleaks(tmp_path: Path) -> None:
    """When --diff is used with gitleaks available, the built-in scanner runs instead."""
    (tmp_path / "clean.py").write_text("x = 1\n")
    cfg = SecretsConfig(prefer_external=True)
    with patch("pipewarden.secrets.shutil.which", return_value="gitleaks"):
        r = scan_secrets(tmp_path, cfg, timeout=30, diff_base="origin/main")
    # Built-in fallback → step name is "secrets:fallback"
    assert r.name == "secrets:fallback"


def test_scan_secrets_falls_back_when_gitleaks_absent(tmp_path: Path) -> None:
    """When gitleaks is not installed, scan_secrets should use the built-in fallback scanner."""
    (tmp_path / "clean.py").write_text("x = 1\n")
    cfg = SecretsConfig(prefer_external=True)
    with patch("pipewarden.secrets.shutil.which", return_value=None):
        r = scan_secrets(tmp_path, cfg, timeout=30)
    assert r.name == "secrets:fallback"


def test_scan_secrets_respects_prefer_external_false(tmp_path: Path) -> None:
    """prefer_external=False always uses the built-in scanner."""
    (tmp_path / "clean.py").write_text("x = 1\n")
    cfg = SecretsConfig(prefer_external=False)
    with patch("pipewarden.secrets.shutil.which", return_value="gitleaks"):
        r = scan_secrets(tmp_path, cfg, timeout=30)
    assert r.name == "secrets:fallback"
