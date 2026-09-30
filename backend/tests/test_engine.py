import pytest
from app.parsers.compose_parser import parse_docker_compose
from app.parsers.terraform_parser import parse_terraform_hcl
from app.parsers.mermaid_parser import parse_mermaid_diagram
from app.engine.stride_rules import evaluate_stride_rules
from app.core.graph import build_graph_and_find_paths
from app.core.models import NodeType, ThreatSeverity, StrideCategory

def test_compose_vulnerable_db():
    compose = """
version: '3.8'
services:
  web:
    image: nginx
    ports:
      - "80:80"
    depends_on:
      - db
  db:
    image: postgres:15
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: "plain_password"
"""
    nodes, edges = parse_docker_compose(compose)
    assert len(nodes) >= 2
    assert any(n.type == NodeType.DATABASE for n in nodes)
    
    threats = evaluate_stride_rules(nodes, edges)
    # Check that critical threat for public database is flagged
    assert any(t.severity == ThreatSeverity.CRITICAL and "Public Database" in t.title for t in threats)
    assert any(t.stride_category == StrideCategory.INFO_DISCLOSURE for t in threats)

    # Attack paths should find ingress to database
    paths, score, summary = build_graph_and_find_paths(nodes, edges, threats)
    assert len(paths) > 0
    assert score < 70  # Low score due to critical DB exposure

def test_terraform_s3_and_rds():
    tf = """
resource "aws_s3_bucket" "test_bucket" {
  bucket = "leaky-bucket"
  acl    = "public-read"
}
resource "aws_db_instance" "test_db" {
  engine = "postgres"
  publicly_accessible = true
}
"""
    nodes, edges = parse_terraform_hcl(tf)
    assert len(nodes) >= 2
    threats = evaluate_stride_rules(nodes, edges)
    assert any("Public Cloud Storage" in t.title for t in threats)
    assert any("Public Database" in t.title for t in threats)

def test_mermaid_unencrypted_flow():
    mermaid = """
flowchart TD
    subgraph "Public Internet"
        User["User Browser"]
    end
    subgraph "Private VPC"
        Backend["App Server"]
        DB[("Postgres DB")]
    end
    User -->|Plaintext HTTP| Backend
    Backend -->|Unencrypted TCP| DB
"""
    nodes, edges = parse_mermaid_diagram(mermaid)
    assert len(nodes) == 3
    threats = evaluate_stride_rules(nodes, edges)
    # Unencrypted cross-boundary link should be flagged
    assert any(t.stride_category == StrideCategory.TAMPERING for t in threats)
