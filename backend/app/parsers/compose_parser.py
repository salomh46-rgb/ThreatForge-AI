import yaml
import re
from typing import Tuple, List, Dict, Any
from app.core.models import NodeModel, EdgeModel, NodeType, TrustZone

def parse_docker_compose(content: str) -> Tuple[List[NodeModel], List[EdgeModel]]:
    nodes: List[NodeModel] = []
    edges: List[EdgeModel] = []

    try:
        data = yaml.safe_load(content)
    except Exception as e:
        raise ValueError(f"Invalid Docker Compose YAML: {str(e)}")

    if not isinstance(data, dict):
        raise ValueError("Docker Compose must be a dictionary")

    services = data.get("services", {})
    if not isinstance(services, dict):
        return nodes, edges

    # Add Internet node if any service has public ports
    has_public_port = False

    for service_name, config in services.items():
        if not isinstance(config, dict):
            continue

        ports_raw = config.get("ports", [])
        ports: List[int] = []
        is_public = False

        for p in ports_raw:
            port_str = str(p)
            is_localhost = ("127.0.0.1" in port_str) or ("localhost" in port_str)
            # Match formats: "80:80", "0.0.0.0:5432:5432", "8080"
            m = re.findall(r"(\d+)", port_str)
            if m:
                host_port = int(m[0]) if len(m) > 1 else int(m[-1])
                ports.append(host_port)
                if not is_localhost:
                    is_public = True

        # Support internal expose declarations
        expose_raw = config.get("expose", [])
        for exp in expose_raw:
            exp_str = str(exp)
            m = re.findall(r"(\d+)", exp_str)
            if m:
                ports.append(int(m[0]))

        if is_public:
            has_public_port = True

        image = str(config.get("image", "")).lower()
        env_vars = {}
        raw_env = config.get("environment", {})
        if isinstance(raw_env, dict):
            env_vars = {str(k): str(v) for k, v in raw_env.items()}
        elif isinstance(raw_env, list):
            for item in raw_env:
                if "=" in str(item):
                    k, v = str(item).split("=", 1)
                    env_vars[k.strip()] = v.strip()

        # Classify Node Type
        node_type = NodeType.MICROSERVICE
        trust_zone = TrustZone.PRIVATE_VPC

        name_lower = service_name.lower()
        if any(db in image or db in name_lower for db in ["postgres", "mysql", "mariadb", "mongo", "database", "db"]):
            node_type = NodeType.DATABASE
            trust_zone = TrustZone.DATA_TIER
        elif any(cache in image or cache in name_lower for cache in ["redis", "memcached", "valkey"]):
            node_type = NodeType.CACHE
            trust_zone = TrustZone.DATA_TIER
        elif any(lb in image or lb in name_lower for lb in ["nginx", "caddy", "traefik", "gateway", "proxy", "envoy", "frontend", "web", "ui"]):
            node_type = NodeType.LOAD_BALANCER if any(x in name_lower for x in ["proxy", "nginx", "frontend", "web", "ui"]) else NodeType.API_GATEWAY
            trust_zone = TrustZone.DMZ
        elif any(auth in image or auth in name_lower for auth in ["keycloak", "auth", "authentik", "oauth"]):
            node_type = NodeType.AUTH_SERVICE
            trust_zone = TrustZone.PRIVATE_VPC
        elif any(q in image or q in name_lower for q in ["rabbitmq", "kafka", "nats", "queue"]):
            node_type = NodeType.QUEUE
            trust_zone = TrustZone.PRIVATE_VPC

        if is_public and trust_zone == TrustZone.PRIVATE_VPC and node_type in [NodeType.DATABASE, NodeType.CACHE]:
            # High risk: DB directly exposed
            pass

        node = NodeModel(
            id=service_name,
            label=service_name.upper(),
            type=node_type,
            trust_zone=trust_zone,
            is_public=is_public,
            ports=ports,
            environment_vars=env_vars,
            properties={
                "image": image or "custom",
                "restart": config.get("restart", "no"),
                "networks": list(config.get("networks", [])) if isinstance(config.get("networks"), (list, dict)) else []
            }
        )
        nodes.append(node)

    # Ingress / Internet Node
    if has_public_port:
        internet_node = NodeModel(
            id="public_internet",
            label="Public Internet / External Clients",
            type=NodeType.INTERNET,
            trust_zone=TrustZone.PUBLIC_INTERNET,
            is_public=True,
            ports=[]
        )
        nodes.insert(0, internet_node)

        # Edges from internet to public services
        for node in nodes:
            if node.id != "public_internet" and node.is_public:
                edges.append(EdgeModel(
                    id=f"edge_internet_{node.id}",
                    source="public_internet",
                    target=node.id,
                    label=f"Port {node.ports[0]}" if node.ports else "Public Ingress",
                    protocol="HTTP/TCP",
                    is_encrypted=any(p in [443, 8443] for p in node.ports),
                    port=node.ports[0] if node.ports else None,
                    crosses_boundary=True
                ))

    # Inter-service Edges from depends_on or environment variable host matches
    for service_name, config in services.items():
        if not isinstance(config, dict):
            continue

        depends = config.get("depends_on", [])
        if isinstance(depends, dict):
            depends = list(depends.keys())
        elif not isinstance(depends, list):
            depends = []

        for target_dep in depends:
            if any(n.id == target_dep for n in nodes):
                edge_id = f"edge_{service_name}_{target_dep}"
                if not any(e.id == edge_id for e in edges):
                    edges.append(EdgeModel(
                        id=edge_id,
                        source=service_name,
                        target=target_dep,
                        label="Depends on",
                        protocol="Internal TCP",
                        is_encrypted=False,
                        crosses_boundary=False
                    ))

        # Check env vars pointing to another service
        raw_env_str = str(config.get("environment", ""))
        for other_node in nodes:
            if other_node.id != service_name and other_node.id != "public_internet":
                if other_node.id in raw_env_str:
                    edge_id = f"edge_{service_name}_{other_node.id}"
                    if not any(e.id == edge_id for e in edges):
                        edges.append(EdgeModel(
                            id=edge_id,
                            source=service_name,
                            target=other_node.id,
                            label="Service Call",
                            protocol="Internal TCP",
                            is_encrypted=False,
                            crosses_boundary=False
                        ))

    return nodes, edges
