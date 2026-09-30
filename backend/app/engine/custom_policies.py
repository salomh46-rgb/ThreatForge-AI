import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.core.models import (
    NodeModel, EdgeModel, ThreatFinding, StrideCategory, ThreatSeverity, NodeType, TrustZone
)

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

# Default Built-In Enterprise Policies
DEFAULT_POLICIES: List[CustomPolicy] = [
    CustomPolicy(
        id="pol_corp_01",
        name="CORP-SEC-01: Zero Direct Public Data Tier Ingress",
        description="Strict isolation rule: No databases or storage repositories may reside in or bind to public network interfaces.",
        target_type="database",
        target_zone="ALL",
        rule_condition="NO_PUBLIC_ACCESS",
        severity=ThreatSeverity.CRITICAL,
        remediation_advice="Remove public IP binding and configure VPC private link or bastion gateway."
    ),
    CustomPolicy(
        id="pol_corp_02",
        name="CORP-SEC-02: Mandatory TLS on All Inter-Zone Crossings",
        description="All traffic crossing between network boundaries must utilize verified TLS 1.3 encryption.",
        target_type="ALL",
        target_zone="ALL",
        rule_condition="FORBID_PLAIN_HTTP",
        severity=ThreatSeverity.HIGH,
        remediation_advice="Upgrade connection to HTTPS/mTLS."
    ),
    CustomPolicy(
        id="pol_corp_03",
        name="CORP-SEC-03: Perimeter WAF Mandatory on Public Entrypoints",
        description="Any load balancer or API gateway facing public internet must be shielded by an application firewall.",
        target_type="load_balancer",
        target_zone="DMZ / Ingress",
        rule_condition="REQUIRE_WAF",
        severity=ThreatSeverity.MEDIUM,
        remediation_advice="Attach AWS WAF WebACL or Cloudflare security proxy."
    )
]

_POLICY_REGISTRY: Dict[str, CustomPolicy] = {p.id: p for p in DEFAULT_POLICIES}

def list_custom_policies() -> List[CustomPolicy]:
    return list(_POLICY_REGISTRY.values())

def add_custom_policy(policy: CustomPolicy) -> CustomPolicy:
    _POLICY_REGISTRY[policy.id] = policy
    return policy

def remove_custom_policy(policy_id: str) -> bool:
    if policy_id in _POLICY_REGISTRY:
        del _POLICY_REGISTRY[policy_id]
        return True
    return False

def evaluate_custom_policies(
    nodes: List[NodeModel],
    edges: List[EdgeModel]
) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []

    for policy in _POLICY_REGISTRY.values():
        if not policy.is_enabled:
            continue

        # Rule 1: NO_PUBLIC_ACCESS
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

        # Rule 2: FORBID_PLAIN_HTTP
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
