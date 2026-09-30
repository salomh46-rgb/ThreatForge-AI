import re
from typing import Tuple, List, Dict, Any
from app.core.models import NodeModel, EdgeModel, NodeType, TrustZone

def parse_terraform_hcl(content: str) -> Tuple[List[NodeModel], List[EdgeModel]]:
    nodes: List[NodeModel] = []
    edges: List[EdgeModel] = []

    # Simple & robust Regex parser for HCL resource blocks
    # e.g.: resource "aws_s3_bucket" "user_uploads" { ... }
    resource_pattern = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{([^\{\}]*(?:\{[^\{\}]*\}[^\{\}]*)*)\}',
        re.MULTILINE | re.DOTALL
    )

    matches = resource_pattern.findall(content)
    has_public_ingress = False

    for res_type, res_name, body in matches:
        node_id = f"{res_type}.{res_name}"
        label = res_name.replace("_", " ").title()
        body_lower = body.lower()

        ports = []
        is_public = False
        n_type = NodeType.MICROSERVICE
        trust_zone = TrustZone.PRIVATE_VPC

        # Detect node type
        if "s3_bucket" in res_type:
            n_type = NodeType.STORAGE_BUCKET
            trust_zone = TrustZone.DATA_TIER
            if "public-read" in body_lower or 'acl = "public' in body_lower or 'block_public_acls = false' in body_lower:
                is_public = True
        elif "db_instance" in res_type or "rds" in res_type or "dynamodb" in res_type:
            n_type = NodeType.DATABASE
            trust_zone = TrustZone.DATA_TIER
            if "publicly_accessible = true" in body_lower or "publicly_accessible=true" in body_lower:
                is_public = True
        elif "elasticache" in res_type or "redis" in res_type:
            n_type = NodeType.CACHE
            trust_zone = TrustZone.DATA_TIER
        elif "lb" in res_type or "alb" in res_type or "elb" in res_type:
            n_type = NodeType.LOAD_BALANCER
            trust_zone = TrustZone.DMZ
            if 'internal = false' in body_lower or 'internal=false' in body_lower or 'internal' not in body_lower:
                is_public = True
        elif "apigateway" in res_type or "api_gateway" in res_type:
            n_type = NodeType.API_GATEWAY
            trust_zone = TrustZone.DMZ
            is_public = True
        elif "security_group" in res_type:
            n_type = NodeType.FIREWALL
            trust_zone = TrustZone.DMZ
            if "0.0.0.0/0" in body:
                is_public = True
        elif "cognito" in res_type or "iam" in res_type:
            n_type = NodeType.AUTH_SERVICE
            trust_zone = TrustZone.PRIVATE_VPC
        elif "sqs" in res_type or "sns" in res_type or "kinesis" in res_type:
            n_type = NodeType.QUEUE
            trust_zone = TrustZone.PRIVATE_VPC
        elif "instance" in res_type or "ecs" in res_type or "lambda" in res_type:
            n_type = NodeType.MICROSERVICE
            if "associate_public_ip_address = true" in body_lower:
                is_public = True

        # Extract port if present
        port_matches = re.findall(r'(?:port|from_port|to_port)\s*=\s*(\d+)', body)
        for p in port_matches:
            ports.append(int(p))

        if is_public:
            has_public_ingress = True

        properties = {
            "resource_type": res_type,
            "raw_body_snippet": body.strip()[:200],
            "encrypted": "storage_encrypted = true" in body_lower or "kms_key_id" in body_lower,
            "public_access": is_public
        }

        node = NodeModel(
            id=node_id,
            label=f"{label} ({res_type.replace('aws_', '')})",
            type=n_type,
            trust_zone=trust_zone,
            is_public=is_public,
            ports=list(set(ports)),
            properties=properties
        )
        nodes.append(node)

    # Ingress / Internet Node
    if has_public_ingress or any(n.is_public for n in nodes):
        internet_node = NodeModel(
            id="public_internet",
            label="Public Internet / External World",
            type=NodeType.INTERNET,
            trust_zone=TrustZone.PUBLIC_INTERNET,
            is_public=True,
            ports=[]
        )
        nodes.insert(0, internet_node)

        for n in nodes:
            if n.id != "public_internet" and n.is_public:
                edges.append(EdgeModel(
                    id=f"edge_internet_{n.id}",
                    source="public_internet",
                    target=n.id,
                    label="Public Ingress (0.0.0.0/0)" if n.type == NodeType.FIREWALL else "Public Access",
                    protocol="HTTP/HTTPS" if 443 in n.ports or 80 in n.ports else "TCP",
                    is_encrypted=443 in n.ports,
                    crosses_boundary=True
                ))

    # Reference based edges: e.g. "aws_security_group.web.id"
    for source_node in nodes:
        snippet = source_node.properties.get("raw_body_snippet", "")
        for target_node in nodes:
            if source_node.id != target_node.id and target_node.id != "public_internet":
                target_short = target_node.id.split(".")[-1]
                if target_short in snippet or target_node.id in snippet:
                    edge_id = f"edge_{source_node.id}_{target_node.id}"
                    if not any(e.id == edge_id for e in edges):
                        edges.append(EdgeModel(
                            id=edge_id,
                            source=source_node.id,
                            target=target_node.id,
                            label="References",
                            protocol="Internal AWS Fabric",
                            is_encrypted=True,
                            crosses_boundary=source_node.trust_zone != target_node.trust_zone
                        ))

    return nodes, edges
