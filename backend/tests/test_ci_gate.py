import pytest
from app.api.ci import evaluate_ci_gate, CIGateRequest

def test_ci_gate_fails_on_critical():
    vulnerable_compose = """
version: '3.8'
services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
"""
    req = CIGateRequest(
        raw_code=vulnerable_compose,
        format="compose",
        fail_on="CRITICAL",
        min_score=70
    )
    res = evaluate_ci_gate(req)
    assert res.passed is False
    assert res.critical_count >= 1
    assert len(res.blocking_violations) >= 1
    assert "FAILED" in res.verdict
    assert "sarif_report" in res.model_dump()
    assert res.sarif_report["version"] == "2.1.0"

def test_ci_gate_passes_on_hardened():
    hardened_tf = """
resource "aws_s3_bucket" "secure_assets" {
  bucket = "company-enterprise-vault"
}
resource "aws_s3_bucket_public_access_block" "guard" {
  bucket = aws_s3_bucket.secure_assets.id
  block_public_acls = true
}
"""
    req = CIGateRequest(
        raw_code=hardened_tf,
        format="terraform",
        fail_on="CRITICAL",
        min_score=70
    )
    res = evaluate_ci_gate(req)
    assert res.passed is True
    assert res.critical_count == 0
    assert "PASSED" in res.verdict

def test_ci_gate_passes_on_project_docker_compose():
    from pathlib import Path
    compose_path = Path(__file__).resolve().parent.parent.parent / "docker-compose.yml"
    assert compose_path.exists()
    content = compose_path.read_text(encoding="utf-8")
    req = CIGateRequest(
        raw_code=content,
        format="compose",
        fail_on="CRITICAL",
        min_score=70
    )
    res = evaluate_ci_gate(req)
    assert res.passed is True
    assert res.critical_count == 0
    assert res.security_score >= 70
    assert "PASSED" in res.verdict
