import re
from typing import Tuple, List, Dict, Any
from app.core.models import NodeModel, EdgeModel, NodeType, TrustZone

def parse_mermaid_diagram(content: str) -> Tuple[List[NodeModel], List[EdgeModel]]:
    nodes_map: Dict[str, NodeModel] = {}
    edges: List[EdgeModel] = []

    lines = content.splitlines()
    current_trust_zone = TrustZone.PRIVATE_VPC

    # Node definitions: e.g. A["Client (Web)"] or A[(Database)] or A[API Gateway]
    node_pattern = re.compile(r'([A-Za-z0-9_]+)\s*(?:\[|\(\[|\{\{|\(\()(["\']?.*?["\']?)(?:\]|\)\]|\}\}|\)\))')
    # Edge definitions: e.g. A -->|HTTP| B or A --- B or A -.-> B
    edge_pattern = re.compile(r'([A-Za-z0-9_]+)\s*(?:-->|---|-.->|==>)\s*(?:\|([^\|]+)\|)?\s*([A-Za-z0-9_]+)')

    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("%%"):
            continue

        # Check subgraphs
        if "subgraph" in line_clean.lower():
            lower = line_clean.lower()
            if "internet" in lower or "public" in lower or "external" in lower:
                current_trust_zone = TrustZone.PUBLIC_INTERNET
            elif "dmz" in lower or "ingress" in lower:
                current_trust_zone = TrustZone.DMZ
            elif "data" in lower or "db" in lower or "storage" in lower:
                current_trust_zone = TrustZone.DATA_TIER
            elif "internal" in lower or "admin" in lower:
                current_trust_zone = TrustZone.INTERNAL_SECURE
            else:
                current_trust_zone = TrustZone.PRIVATE_VPC
            continue
        elif line_clean.lower() == "end":
            current_trust_zone = TrustZone.PRIVATE_VPC
            continue

        # Extract edges
        edge_matches = edge_pattern.findall(line_clean)
        for src, protocol_label, tgt in edge_matches:
            # Register src if missing
            if src not in nodes_map:
                nodes_map[src] = NodeModel(
                    id=src,
                    label=src.replace("_", " ").title(),
                    type=_guess_type(src),
                    trust_zone=current_trust_zone,
                    is_public=current_trust_zone == TrustZone.PUBLIC_INTERNET
                )
            if tgt not in nodes_map:
                nodes_map[tgt] = NodeModel(
                    id=tgt,
                    label=tgt.replace("_", " ").title(),
                    type=_guess_type(tgt),
                    trust_zone=current_trust_zone,
                    is_public=current_trust_zone == TrustZone.PUBLIC_INTERNET
                )

            label = protocol_label.strip() if protocol_label else "TCP"
            is_enc = any(p in label.lower() for p in ["https", "tls", "ssl", "grpc", "ssh", "443"])
            if "http" in label.lower() and "https" not in label.lower():
                is_enc = False
            elif "plaintext" in label.lower() or "unencrypted" in label.lower():
                is_enc = False

            edges.append(EdgeModel(
                id=f"edge_{src}_{tgt}",
                source=src,
                target=tgt,
                label=label,
                protocol=label,
                is_encrypted=is_enc,
                crosses_boundary=nodes_map[src].trust_zone != nodes_map[tgt].trust_zone
            ))

        # Extract node details
        node_matches = node_pattern.findall(line_clean)
        for n_id, n_label in node_matches:
            clean_label = n_label.strip("\"'[]()")
            n_type = _guess_type(clean_label or n_id)
            is_pub = current_trust_zone == TrustZone.PUBLIC_INTERNET or "public" in clean_label.lower() or "internet" in clean_label.lower()

            if n_id in nodes_map:
                nodes_map[n_id].label = clean_label
                nodes_map[n_id].type = n_type
                nodes_map[n_id].is_public = is_pub
            else:
                nodes_map[n_id] = NodeModel(
                    id=n_id,
                    label=clean_label,
                    type=n_type,
                    trust_zone=current_trust_zone,
                    is_public=is_pub
                )

    return list(nodes_map.values()), edges

def _guess_type(name: str) -> NodeType:
    n = name.lower()
    if any(k in n for k in ["internet", "client", "user", "browser", "attacker"]):
        return NodeType.INTERNET
    if any(k in n for k in ["db", "database", "postgres", "sql", "mongo", "mysql"]):
        return NodeType.DATABASE
    if any(k in n for k in ["redis", "cache", "memcached"]):
        return NodeType.CACHE
    if any(k in n for k in ["s3", "bucket", "storage", "blob"]):
        return NodeType.STORAGE_BUCKET
    if any(k in n for k in ["gateway", "kong", "envoy", "ingress"]):
        return NodeType.API_GATEWAY
    if any(k in n for k in ["nginx", "caddy", "load balancer", "alb", "elb"]):
        return NodeType.LOAD_BALANCER
    if any(k in n for k in ["auth", "keycloak", "identity", "oauth"]):
        return NodeType.AUTH_SERVICE
    if any(k in n for k in ["firewall", "waf", "shield"]):
        return NodeType.FIREWALL
    if any(k in n for k in ["kafka", "queue", "rabbitmq"]):
        return NodeType.QUEUE
    return NodeType.MICROSERVICE
