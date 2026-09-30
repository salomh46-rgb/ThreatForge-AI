import networkx as nx
from typing import List, Dict, Any, Tuple
from app.core.models import (
    NodeModel, EdgeModel, ThreatFinding, AttackPath, ThreatSeverity, NodeType
)

def build_graph_and_find_paths(
    nodes: List[NodeModel],
    edges: List[EdgeModel],
    threats: List[ThreatFinding]
) -> Tuple[List[AttackPath], int, Dict[str, Any]]:
    G = nx.DiGraph()

    for n in nodes:
        G.add_node(n.id, label=n.label, type=n.type, is_public=n.is_public)

    for e in edges:
        G.add_edge(e.source, e.target, id=e.id, protocol=e.protocol, encrypted=e.is_encrypted)

    # Update threat counts on nodes
    for node in nodes:
        node_threats = [t for t in threats if t.target_id == node.id]
        node.threat_count = len(node_threats)
        if any(t.severity == ThreatSeverity.CRITICAL for t in node_threats):
            node.highest_severity = ThreatSeverity.CRITICAL
        elif any(t.severity == ThreatSeverity.HIGH for t in node_threats):
            node.highest_severity = ThreatSeverity.HIGH
        elif any(t.severity == ThreatSeverity.MEDIUM for t in node_threats):
            node.highest_severity = ThreatSeverity.MEDIUM
        elif any(t.severity == ThreatSeverity.LOW for t in node_threats):
            node.highest_severity = ThreatSeverity.LOW

    # Find entry nodes (public internet or public nodes)
    entry_nodes = [n.id for n in nodes if n.is_public]
    target_nodes = [n.id for n in nodes if n.type in [NodeType.DATABASE, NodeType.STORAGE_BUCKET, NodeType.CACHE]]

    attack_paths: List[AttackPath] = []
    path_counter = 1

    for src in entry_nodes:
        for tgt in target_nodes:
            if src == tgt:
                # Direct attack on exposed target
                target_node = next((n for n in nodes if n.id == tgt), None)
                attack_paths.append(AttackPath(
                    id=f"path_{path_counter}",
                    name=f"Direct Exploit: Internet -> {target_node.label if target_node else tgt}",
                    entry_node_id=src,
                    target_node_id=tgt,
                    path_nodes=[src],
                    description=f"Direct zero-barrier compromise: '{target_node.label if target_node else tgt}' is exposed directly on the public network.",
                    risk_level=ThreatSeverity.CRITICAL
                ))
                path_counter += 1
                continue

            if nx.has_path(G, src, tgt):
                try:
                    all_paths = list(nx.all_simple_paths(G, src, tgt, cutoff=5))
                    for p in all_paths[:2]:  # Top 2 most dangerous paths
                        target_node = next((n for n in nodes if n.id == tgt), None)
                        src_node = next((n for n in nodes if n.id == src), None)
                        
                        # Calculate risk of path
                        has_crit = any(
                            any(t.severity == ThreatSeverity.CRITICAL for t in threats if t.target_id == nid)
                            for nid in p
                        )
                        risk = ThreatSeverity.CRITICAL if has_crit else ThreatSeverity.HIGH

                        path_name = f"Infiltration Chain: {src_node.label if src_node else src} -> {target_node.label if target_node else tgt}"
                        desc = " -> ".join([next((n.label for n in nodes if n.id == nid), nid) for nid in p])

                        attack_paths.append(AttackPath(
                            id=f"path_{path_counter}",
                            name=path_name,
                            entry_node_id=src,
                            target_node_id=tgt,
                            path_nodes=p,
                            description=f"Exploit pivot chain: {desc}",
                            risk_level=risk
                        ))
                        path_counter += 1
                except Exception:
                    pass

    # Calculate Security Score (0 - 100)
    score = 100
    crit_count = sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL)
    high_count = sum(1 for t in threats if t.severity == ThreatSeverity.HIGH)
    med_count = sum(1 for t in threats if t.severity == ThreatSeverity.MEDIUM)
    low_count = sum(1 for t in threats if t.severity == ThreatSeverity.LOW)

    score -= (crit_count * 25)
    score -= (high_count * 12)
    score -= (med_count * 6)
    score -= (low_count * 2)

    score = max(5, min(100, score))

    summary = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "total_threats": len(threats),
        "critical_threats": crit_count,
        "high_threats": high_count,
        "medium_threats": med_count,
        "low_threats": low_count,
        "attack_paths_count": len(attack_paths),
        "security_grade": "A" if score >= 90 else ("B" if score >= 75 else ("C" if score >= 50 else "F"))
    }

    return attack_paths, score, summary
