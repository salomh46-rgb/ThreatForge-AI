import uuid
from typing import List
from pydantic import BaseModel, Field
from app.core.models import (
    NodeModel, EdgeModel, ThreatFinding, StrideCategory, ThreatSeverity, NodeType
)
from app.core.database import get_connection, log_audit_event

class CustomPolicy(BaseModel):
    id: str = Field(default_factory=lambda: f"pol_{str(uuid.uuid4())[:6]}")
    name: str
    description: str
    target_type: str = "ALL"  # database, cache, storage_bucket, ALL
    target_zone: str = "ALL"  # Secure Data Tier, DMZ / Ingress, ALL
    rule_condition: str  # NO_PUBLIC_ACCESS, REQUIRE_ENCRYPTION, FORBID_PLAIN_HTTP, REQUIRE_WAF
    severity: ThreatSeverity = ThreatSeverity.HIGH
    remediation_advice: str
    is_enabled: bool = True

DEFAULT_POLICIES = [
    (
        "pol_corp_01",
        "CORP-SEC-01: Zero Direct Public Data Tier Ingress",
        "Strict isolation rule: No databases or storage repositories may reside in or bind to public network interfaces.",
        "database",
        "ALL",
        "NO_PUBLIC_ACCESS",
        "CRITICAL",
        "Remove public IP binding and configure VPC private link or bastion gateway."
    ),
    (
        "pol_corp_02",
        "CORP-SEC-02: Mandatory TLS on All Inter-Zone Crossings",
        "All traffic crossing between network boundaries must utilize verified TLS 1.3 encryption.",
        "ALL",
        "ALL",
        "FORBID_PLAIN_HTTP",
        "HIGH",
        "Upgrade connection to HTTPS/mTLS."
    ),
    (
        "pol_corp_03",
        "CORP-SEC-03: Perimeter WAF Mandatory on Public Entrypoints",
        "Any load balancer or API gateway facing public internet must be shielded by an application firewall.",
        "load_balancer",
        "DMZ / Ingress",
        "REQUIRE_WAF",
        "MEDIUM",
        "Attach AWS WAF WebACL or Cloudflare security proxy."
    )
]

def seed_default_policies():
    with get_connection() as conn:
        cursor = conn.cursor()
        for p in DEFAULT_POLICIES:
            cursor.execute("""
                INSERT OR IGNORE INTO custom_policies (id, name, description, target_type, target_zone, rule_condition, severity, remediation_advice, is_enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, p)
        conn.commit()

def list_custom_policies() -> List[CustomPolicy]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM custom_policies")
        rows = cursor.fetchall()
        if not rows:
            seed_default_policies()
            cursor.execute("SELECT * FROM custom_policies")
            rows = cursor.fetchall()
        
        result = []
        for r in rows:
            d = dict(r)
            d["is_enabled"] = bool(d["is_enabled"])
            result.append(CustomPolicy(**d))
        return result

def add_custom_policy(policy: CustomPolicy, actor: str = "Lead Architect") -> CustomPolicy:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO custom_policies (id, name, description, target_type, target_zone, rule_condition, severity, remediation_advice, is_enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            policy.id,
            policy.name,
            policy.description,
            policy.target_type,
            policy.target_zone,
            policy.rule_condition,
            policy.severity.value,
            policy.remediation_advice,
            1 if policy.is_enabled else 0
        ))
        conn.commit()

    log_audit_event(
        event_type="POLICY_CREATED",
        actor=actor,
        target=policy.id,
        details=f"Defined policy '{policy.name}' condition: {policy.rule_condition}"
    )
    return policy

def remove_custom_policy(policy_id: str, actor: str = "Lead Architect") -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM custom_policies WHERE id = ?", (policy_id,))
        affected = cursor.rowcount
        conn.commit()

    if affected > 0:
        log_audit_event(
            event_type="POLICY_DELETED",
            actor=actor,
            target=policy_id,
            details=f"Deleted organizational policy {policy_id}"
        )
        return True
    return False

def evaluate_custom_policies(
    nodes: List[NodeModel],
    edges: List[EdgeModel]
) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    policies = list_custom_policies()

    for policy in policies:
        if not policy.is_enabled:
            continue

        if policy.rule_condition == "NO_PUBLIC_ACCESS":
            for n in nodes:
                matches_type = policy.target_type == "ALL" or n.type.value == policy.target_type
                matches_zone = policy.target_zone == "ALL" or n.trust_zone.value == policy.target_zone
                if matches_type and matches_zone and n.is_public and n.type != NodeType.INTERNET:
                    findings.append(ThreatFinding(
                        id=f"custom_viol_{policy.id}_{n.id}",
                        target_id=n.id,
                        target_name=n.label,
                        stride_category=StrideCategory.INFO_DISCLOSURE,
                        title=f"Custom Policy Violation: {policy.name}",
                        description=f"{n.label} violates organization policy '{policy.name}': {policy.description}",
                        severity=policy.severity,
                        cvss_score=8.8 if policy.severity == ThreatSeverity.CRITICAL else 7.2,
                        mitre_technique="T1078 - Corporate Security Policy Violation",
                        blast_radius_nodes=[n.id],
                        remediation_advice=policy.remediation_advice
                    ))

        elif policy.rule_condition == "FORBID_PLAIN_HTTP":
            for e in edges:
                if e.crosses_boundary and not e.is_encrypted:
                    findings.append(ThreatFinding(
                        id=f"custom_viol_{policy.id}_{e.id}",
                        target_id=e.id,
                        target_name=f"{e.source} -> {e.target}",
                        stride_category=StrideCategory.TAMPERING,
                        title=f"Custom Policy Violation: {policy.name}",
                        description=f"Flow {e.source} -> {e.target} violates organizational crypto standard: {policy.description}",
                        severity=policy.severity,
                        cvss_score=7.4,
                        mitre_technique="T1040 - In-Transit Cryptographic Policy Breach",
                        blast_radius_nodes=[e.source, e.target],
                        remediation_advice=policy.remediation_advice
                    ))

    return findings
