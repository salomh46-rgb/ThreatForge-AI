import pytest
from app.api.compliance import run_compliance_audit, ComplianceAuditRequest

def test_vulnerable_architecture_compliance_fails():
    code = """
version: '3.8'
services:
  db:
    image: postgres
    ports: ["5432:5432"]
"""
    req = ComplianceAuditRequest(raw_code=code, format="compose")
    report = run_compliance_audit(req)
    assert report.overall_compliance < 100
    assert "pci_dss" in report.frameworks
    assert "iso_27001" in report.frameworks
    assert "khm_uz" in report.frameworks
    assert report.frameworks["khm_uz"].compliance_percentage < 100

def test_hardened_architecture_compliance_passes():
    code = """
resource "aws_s3_bucket" "vault" {
  bucket = "clean-vault"
}
resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.vault.id
  block_public_acls = true
}
"""
    req = ComplianceAuditRequest(raw_code=code, format="terraform")
    report = run_compliance_audit(req)
    assert report.overall_compliance >= 75
