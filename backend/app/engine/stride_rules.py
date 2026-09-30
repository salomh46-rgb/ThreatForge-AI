import uuid
from typing import List
from app.core.models import (
    NodeModel, EdgeModel, ThreatFinding, StrideCategory, ThreatSeverity, NodeType, TrustZone
)

def evaluate_stride_rules(nodes: List[NodeModel], edges: List[EdgeModel]) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []

    # Map node id to node object
    node_map = {n.id: n for n in nodes}

    # Helper to find nodes reachable from a given node
    def get_downstream_nodes(start_id: str) -> List[str]:
        visited = set()
        queue = [start_id]
        while queue:
            curr = queue.pop(0)
            for e in edges:
                if e.source == curr and e.target not in visited:
                    visited.add(e.target)
                    queue.append(e.target)
        return list(visited)

    # 1. Direct Public Database Exposure
    for node in nodes:
        if node.type == NodeType.DATABASE and node.is_public:
            blast = get_downstream_nodes(node.id)
            findings.append(ThreatFinding(
                id=f"threat_pub_db_{node.id}",
                target_id=node.id,
                target_name=node.label,
                stride_category=StrideCategory.INFO_DISCLOSURE,
                title="Direct Public Database Exposure (0.0.0.0/0)",
                description=f"Database '{node.label}' has public ports bound to the internet. Attackers can perform brute-force attacks or exploit zero-day RCE vulnerabilities directly.",
                severity=ThreatSeverity.CRITICAL,
                cvss_score=9.8,
                mitre_technique="T1190 - Exploit Public-Facing Application",
                blast_radius_nodes=[node.id] + blast,
                remediation_advice="Move database to private subnet (Data Tier) and remove public port mapping. Expose only via internal microservices.",
                code_patch="""# Security Remediation:
# BEFORE (Vulnerable):
#   ports: ["5432:5432"]
# AFTER (Secured):
#   expose: ["5432"] # Only reachable within internal container network"""
            ))

    # 2. Public Cache Exposure (Redis / Memcached)
    for node in nodes:
        if node.type == NodeType.CACHE and node.is_public:
            blast = get_downstream_nodes(node.id)
            findings.append(ThreatFinding(
                id=f"threat_pub_cache_{node.id}",
                target_id=node.id,
                target_name=node.label,
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                title="Public In-Memory Cache (Redis RCE Risk)",
                description=f"Cache instance '{node.label}' is exposed without boundary controls. Attackers can execute arbitrary commands via CONFIG SET or flush session tokens.",
                severity=ThreatSeverity.CRITICAL,
                cvss_score=9.4,
                mitre_technique="T1552 - Unsecured Credentials & In-Memory Secrets",
                blast_radius_nodes=[node.id] + blast,
                remediation_advice="Bind Redis to 127.0.0.1 or VPC private network only. Enable TLS and strong requirepass authentication.",
                code_patch="""# Security Remediation:
# BEFORE:
#   ports: ["6379:6379"]
# AFTER:
#   expose: ["6379"]
#   command: redis-server --requirepass ${STRONG_REDIS_PASSWORD} --tls-port 6379"""
            ))

    # 3. Public Storage Bucket
    for node in nodes:
        if node.type == NodeType.STORAGE_BUCKET and node.is_public:
            findings.append(ThreatFinding(
                id=f"threat_pub_s3_{node.id}",
                target_id=node.id,
                target_name=node.label,
                stride_category=StrideCategory.INFO_DISCLOSURE,
                title="Unrestricted Public Cloud Storage Bucket",
                description=f"Storage bucket '{node.label}' allows public read or lacks S3 Block Public Access policies. Risk of mass data leakage of PII or proprietary assets.",
                severity=ThreatSeverity.HIGH,
                cvss_score=8.2,
                mitre_technique="T1530 - Data from Cloud Storage Object",
                blast_radius_nodes=[node.id],
                remediation_advice="Enforce aws_s3_bucket_public_access_block with all flags set to true. Use CloudFront OAI or presigned URLs for client uploads.",
                code_patch="""# Terraform S3 Block Public Access:
resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.user_uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"""
            ))

    # 4. Unencrypted Cross-Boundary Traffic (Man-In-The-Middle / Tampering)
    for edge in edges:
        src = node_map.get(edge.source)
        tgt = node_map.get(edge.target)
        if src and tgt and edge.crosses_boundary and not edge.is_encrypted:
            findings.append(ThreatFinding(
                id=f"threat_edge_{edge.id}",
                target_id=edge.id,
                target_name=f"{src.label} -> {tgt.label}",
                stride_category=StrideCategory.TAMPERING,
                title=f"Unencrypted Cross-Zone Link ({edge.protocol})",
                description=f"Traffic flowing from '{src.label}' to '{tgt.label}' crosses trust boundary '{src.trust_zone}' to '{tgt.trust_zone}' without TLS encryption. Sensitive payload can be intercepted.",
                severity=ThreatSeverity.HIGH,
                cvss_score=7.5,
                mitre_technique="T1040 - Network Sniffing",
                blast_radius_nodes=[edge.source, edge.target],
                remediation_advice="Upgrade connection from plaintext HTTP/TCP to HTTPS / mTLS with mutual certificate verification.",
                code_patch="""# Enforce TLS 1.3:
# Change: http://internal-service:8080
# To:     https://internal-service:8443
# Enforce SSL certificate verification in HTTP client config"""
            ))

    # 5. Missing Ingress WAF / Layer 7 DoS Protection
    has_waf = any(n.type == NodeType.FIREWALL for n in nodes)
    public_gateways = [n for n in nodes if n.is_public and n.type in [NodeType.LOAD_BALANCER, NodeType.API_GATEWAY]]
    if public_gateways and not has_waf:
        for gw in public_gateways:
            findings.append(ThreatFinding(
                id=f"threat_dos_{gw.id}",
                target_id=gw.id,
                target_name=gw.label,
                stride_category=StrideCategory.DENIAL_OF_SERVICE,
                title="Missing Web Application Firewall (WAF) & Rate Limiting",
                description=f"Public ingress point '{gw.label}' lacks an upstream WAF. Vulnerable to HTTP flood, slowloris attacks, and automated brute-force scraping.",
                severity=ThreatSeverity.MEDIUM,
                cvss_score=6.5,
                mitre_technique="T1498 - Network Denial of Service",
                blast_radius_nodes=[gw.id] + get_downstream_nodes(gw.id),
                remediation_advice="Attach AWS WAF / Cloudflare with rate-limiting rules (e.g. max 100 req/min per IP) and OWASP Core Rule Set.",
                code_patch="""# Attach AWS WAFv2 Web ACL:
resource "aws_wafv2_web_acl_association" "alb_assoc" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.rate_limit_acl.arn
}"""
            ))

    # 6. Hardcoded Secrets in Environment Variables
    for node in nodes:
        if node.environment_vars:
            secret_keys = []
            for k, v in node.environment_vars.items():
                k_lower = k.lower()
                if any(s in k_lower for s in ["password", "secret", "token", "private_key", "api_key", "auth"]):
                    if v and not v.startswith("${") and not v.startswith("$"):
                        secret_keys.append(k)

            if secret_keys:
                findings.append(ThreatFinding(
                    id=f"threat_env_secret_{node.id}",
                    target_id=node.id,
                    target_name=node.label,
                    stride_category=StrideCategory.INFO_DISCLOSURE,
                    title=f"Hardcoded Secrets in Environment: {', '.join(secret_keys[:2])}",
                    description=f"Node '{node.label}' contains plaintext secrets in configuration. Container inspection (`docker inspect`) or git history leaks will compromise database/API credentials.",
                    severity=ThreatSeverity.HIGH,
                    cvss_score=8.4,
                    mitre_technique="T1552.001 - Credentials in Files & Environment",
                    blast_radius_nodes=[node.id],
                    remediation_advice="Extract secrets into environment secrets provider (Vault, AWS Secrets Manager, Doppler, or Docker Secrets).",
                    code_patch="""# BEFORE:
#   DB_PASSWORD: "super_secret_password_123"
# AFTER:
#   DB_PASSWORD: ${DB_PASSWORD_SECRET} # Injected at runtime via Secrets Manager"""
                ))

    # 7. Unauthenticated Public Microservice (Spoofing & Privilege Escalation)
    has_auth_service = any(n.type == NodeType.AUTH_SERVICE for n in nodes)
    for node in nodes:
        if node.type == NodeType.MICROSERVICE and node.is_public:
            findings.append(ThreatFinding(
                id=f"threat_no_auth_{node.id}",
                target_id=node.id,
                target_name=node.label,
                stride_category=StrideCategory.SPOOFING,
                title="Public Microservice Without Centralized Auth Gateway",
                description=f"Service '{node.label}' is directly exposed to the internet. Missing OAuth2/JWT verification layer exposes business logic to spoofed requests.",
                severity=ThreatSeverity.HIGH,
                cvss_score=8.1,
                mitre_technique="T1078 - Valid Accounts / Bypass Authentication",
                blast_radius_nodes=[node.id] + get_downstream_nodes(node.id),
                remediation_advice="Route traffic through an API Gateway or Identity Provider (Keycloak / Auth0) before hitting internal business services.",
                code_patch="""# Add API Gateway Route with Auth Policy:
# Enforce Bearer JWT validation at Ingress Controller before forwarding."""
            ))

    # 8. Missing Audit Logging / Non-Repudiation on Data Tier
    for node in nodes:
        if node.type == NodeType.DATABASE:
            findings.append(ThreatFinding(
                id=f"threat_repudiation_{node.id}",
                target_id=node.id,
                target_name=node.label,
                stride_category=StrideCategory.REPUDIATION,
                title="Insufficient Database Query Audit Logging",
                description=f"Database '{node.label}' lacks explicit security audit logging. Malicious insider activity or SQL injection data exfiltration cannot be forensically proven.",
                severity=ThreatSeverity.LOW,
                cvss_score=3.8,
                mitre_technique="T1562 - Impair Defenses (Lack of Audit Trail)",
                blast_radius_nodes=[node.id],
                remediation_advice="Enable pgAudit / MySQL General Query Log and stream immutable logs to centralized SIEM / CloudWatch.",
                code_patch="""# PostgreSQL Audit Configuration:
# shared_preload_libraries = 'pgaudit'
# pgaudit.log = 'all, -misc'"""
            ))

    return findings
