import pytest
from app.core.security import validate_webhook_url
from app.core.database import init_db, get_audit_logs
from app.engine.risk_acceptance import create_risk_exception, list_risk_exceptions
from app.engine.custom_policies import list_custom_policies

def test_ssrf_validator_blocks_malicious_urls():
    # 1. Block cloud metadata
    with pytest.raises(ValueError, match="SSRF Protection"):
        validate_webhook_url("http://169.254.169.254/latest/meta-data")

    # 2. Block localhost / loopback
    with pytest.raises(ValueError, match="SSRF Protection"):
        validate_webhook_url("http://127.0.0.1:8000/internal-admin")

    # 3. Block plaintext HTTP
    with pytest.raises(ValueError, match="HTTPS"):
        validate_webhook_url("http://hooks.slack.com/services/123")

    # 4. Block non-whitelisted domain
    with pytest.raises(ValueError, match="SSRF Protection"):
        validate_webhook_url("https://malicious-attacker-server.com/drain")

def test_ssrf_validator_allows_valid_webhook():
    valid = validate_webhook_url("https://hooks.slack.com/services/T000/B000/XXXX")
    assert valid.startswith("https://hooks.slack.com")

def test_sqlite_persistence_and_audit_logging():
    init_db()

    # Create risk exception
    exc = create_risk_exception(
        threat_id="threat_test_01",
        threat_title="Test Public DB",
        target_node="postgres_primary",
        justification="Verified test isolation in staging",
        approved_by="Auditor Jasper",
        days_valid=30
    )

    assert exc.id is not None
    assert exc.status == "ACTIVE"

    # Verify exception is persisted in SQLite
    all_exceptions = list_risk_exceptions()
    assert any(e.id == exc.id for e in all_exceptions)

    # Verify immutable audit log recorded the event
    logs = get_audit_logs()
    assert len(logs) > 0
    assert any(l["event_type"] == "RISK_EXCEPTION_CREATED" and l["actor"] == "Auditor Jasper" for l in logs)

def test_custom_policies_seeded_in_sqlite():
    init_db()
    policies = list_custom_policies()
    assert len(policies) >= 3
    assert any(p.id == "pol_corp_01" for p in policies)
