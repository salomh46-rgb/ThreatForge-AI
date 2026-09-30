from typing import Tuple, List
from app.core.models import NodeModel, EdgeModel
from app.parsers.compose_parser import parse_docker_compose
from app.parsers.terraform_parser import parse_terraform_hcl
from app.parsers.mermaid_parser import parse_mermaid_diagram

def parse_architecture(raw_code: str, fmt: str = "auto") -> Tuple[List[NodeModel], List[EdgeModel], str]:
    cleaned = raw_code.strip()
    if not cleaned:
        raise ValueError("Architecture code cannot be empty")

    detected_format = fmt.lower()

    if detected_format == "auto":
        if "version:" in cleaned and "services:" in cleaned:
            detected_format = "compose"
        elif "resource \"" in cleaned or "provider \"" in cleaned or "terraform {" in cleaned:
            detected_format = "terraform"
        elif any(k in cleaned for k in ["flowchart", "graph TD", "graph LR", "-->", "subgraph"]):
            detected_format = "mermaid"
        else:
            # Fallback heuristic: Try compose first, then mermaid
            if ":" in cleaned and ("image:" in cleaned or "ports:" in cleaned):
                detected_format = "compose"
            else:
                detected_format = "mermaid"

    if detected_format in ["compose", "docker-compose", "yaml", "yml"]:
        nodes, edges = parse_docker_compose(cleaned)
        return nodes, edges, "Docker Compose"
    elif detected_format in ["terraform", "tf", "hcl"]:
        nodes, edges = parse_terraform_hcl(cleaned)
        return nodes, edges, "Terraform HCL"
    elif detected_format in ["mermaid", "mmd"]:
        nodes, edges = parse_mermaid_diagram(cleaned)
        return nodes, edges, "Mermaid Diagram"
    else:
        # Default try mermaid
        nodes, edges = parse_mermaid_diagram(cleaned)
        return nodes, edges, "Generic Graph"
