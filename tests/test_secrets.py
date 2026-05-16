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


# ---------------------------------------------------------------------------
# Database URI connection strings
# ---------------------------------------------------------------------------

def test_postgres_connection_string_detected(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text('DSN = "postgresql://admin:s3cr3t@db.example.com/prod"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "postgres.connection_string" for f in r.findings)


def test_mysql_connection_string_detected(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text('URL = "mysql://root:p@ssword@127.0.0.1/mydb"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "mysql.connection_string" for f in r.findings)


def test_redis_connection_string_with_password_detected(tmp_path: Path) -> None:
    (tmp_path / "cache.py").write_text('REDIS_URL = "redis://:supersecret@redis.host:6379/0"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "redis.connection_string" for f in r.findings)


def test_redis_url_without_password_not_detected(tmp_path: Path) -> None:
    (tmp_path / "cache.py").write_text('REDIS_URL = "redis://localhost:6379"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    # No credentials → should not flag as redis.connection_string
    assert not any(f.rule_id == "redis.connection_string" for f in r.findings)


def test_amqp_connection_string_detected(tmp_path: Path) -> None:
    (tmp_path / "mq.py").write_text('URL = "amqp://guest:guest123@rabbitmq.host/vhost"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "amqp.connection_string" for f in r.findings)


def test_mssql_connection_string_detected(tmp_path: Path) -> None:
    conn = "Server=myserver.database.windows.net;Database=mydb;User Id=admin;Password=Secr3t!;\n"
    (tmp_path / "app.config").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "mssql.connection_string" for f in r.findings)


def test_mssql_integrated_security_not_detected(tmp_path: Path) -> None:
    conn = "Server=myserver;Database=mydb;Integrated Security=SSPI;\n"
    (tmp_path / "app.config").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert not any(f.rule_id == "mssql.connection_string" for f in r.findings)


def test_jdbc_connection_string_detected(tmp_path: Path) -> None:
    url = 'jdbc:postgresql://db.host:5432/prod?user=admin&password=s3cretPass\n'
    (tmp_path / "datasource.properties").write_text(url)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "jdbc.connection_string" for f in r.findings)


def test_jdbc_sqlserver_semicolon_params_detected(tmp_path: Path) -> None:
    url = "jdbc:sqlserver://host:1433;databaseName=mydb;user=sa;password=P@ssw0rd\n"
    (tmp_path / "db.props").write_text(url)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "jdbc.connection_string" for f in r.findings)


# ---------------------------------------------------------------------------
# Azure connection strings
# ---------------------------------------------------------------------------

def test_azure_storage_connection_string_detected(tmp_path: Path) -> None:
    key = "A" * 43 + "="
    conn = f"DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey={key};\n"
    (tmp_path / "appsettings.json").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "azure.storage_connection_string" for f in r.findings)


def test_azure_cosmos_connection_string_detected(tmp_path: Path) -> None:
    key = "B" * 43 + "="
    conn = f"AccountEndpoint=https://myaccount.documents.azure.com:443/;AccountKey={key};\n"
    (tmp_path / "cosmos.txt").write_text(conn)
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "azure.cosmos_connection_string" for f in r.findings)


def test_azure_servicebus_connection_string_detected(tmp_path: Path) -> None:
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
    (tmp_path / "env.txt").write_text("AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "aws.sts_key" for f in r.findings)


# ---------------------------------------------------------------------------
# Developer platform tokens
# ---------------------------------------------------------------------------

def test_digitalocean_token_detected(tmp_path: Path) -> None:
    token = "dop_v1_" + "a" * 64
    (tmp_path / "tf.tf").write_text(f'token = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "digitalocean.token" for f in r.findings)


def test_github_actions_token_detected(tmp_path: Path) -> None:
    token = "ghs_" + "A" * 36
    (tmp_path / "script.sh").write_text(f"TOKEN={token}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "github.actions_token" for f in r.findings)


def test_github_user_token_detected(tmp_path: Path) -> None:
    token = "ghu_" + "B" * 36
    (tmp_path / "script.sh").write_text(f"TOKEN={token}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "github.user_token" for f in r.findings)


def test_linear_api_key_detected(tmp_path: Path) -> None:
    token = "lin_api_" + "x" * 40
    (tmp_path / "linear.py").write_text(f'API_KEY = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "linear.api_key" for f in r.findings)


def test_okta_token_detected(tmp_path: Path) -> None:
    token = "SSWS " + "A" * 42
    (tmp_path / "okta.py").write_text(f'AUTH = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "okta.token" for f in r.findings)


# ---------------------------------------------------------------------------
# AI / ML platform tokens
# ---------------------------------------------------------------------------

def test_huggingface_token_detected(tmp_path: Path) -> None:
    token = "hf_" + "A" * 34
    (tmp_path / "model.py").write_text(f'HF_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "huggingface.token" for f in r.findings)


def test_replicate_token_detected(tmp_path: Path) -> None:
    token = "r8_" + "A" * 37
    (tmp_path / "gen.py").write_text(f'TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "replicate.token" for f in r.findings)


# ---------------------------------------------------------------------------
# Communication tokens
# ---------------------------------------------------------------------------

def test_telegram_bot_token_detected(tmp_path: Path) -> None:
    token = "123456789:AA" + "B" * 33
    (tmp_path / "bot.py").write_text(f'BOT_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "telegram.bot_token" for f in r.findings)


# ---------------------------------------------------------------------------
# Payment — additional
# ---------------------------------------------------------------------------

def test_stripe_test_key_detected(tmp_path: Path) -> None:
    token = "sk_test_" + "a" * 24
    (tmp_path / "pay.py").write_text(f'STRIPE_KEY = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "stripe.test_key" for f in r.findings)


def test_stripe_webhook_secret_detected(tmp_path: Path) -> None:
    token = "whsec_" + "a" * 32
    (tmp_path / "webhook.py").write_text(f'SECRET = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "stripe.webhook_secret" for f in r.findings)


# ---------------------------------------------------------------------------
# E-commerce
# ---------------------------------------------------------------------------

def test_shopify_access_token_detected(tmp_path: Path) -> None:
    token = "shpat_" + "a" * 32
    (tmp_path / "shop.py").write_text(f'ACCESS_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "shopify.access_token" for f in r.findings)


def test_shopify_storefront_token_detected(tmp_path: Path) -> None:
    token = "shpss_" + "b" * 32
    (tmp_path / "shop.py").write_text(f'SF_TOKEN = "{token}"\n')
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "shopify.storefront_token" for f in r.findings)


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

def test_newrelic_license_key_detected(tmp_path: Path) -> None:
    key = "NRAK-" + "A" * 32
    (tmp_path / "newrelic.ini").write_text(f"license_key = {key}\n")
    r = scan_secrets_fallback(tmp_path, SecretsConfig())
    assert r.status == Status.FAILED
    assert any(f.rule_id == "newrelic.license_key" for f in r.findings)
