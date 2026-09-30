from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from app.core.models import ArchitectureTopology, ThreatSeverity
from app.parsers.generic_parser import parse_architecture
from app.engine.stride_rules import evaluate_stride_rules
from app.core.graph import build_graph_and_find_paths
from app.engine.sarif import generate_sarif

router = APIRouter(prefix="/api/ci", tags=["CI/CD Gate"])

class CIGateRequest(BaseModel):
    raw_code: str
    format: str = "auto"
    fail_on: str = "CRITICAL"  # CRITICAL, HIGH, MEDIUM, LOW
    min_score: int = 70
    pr_number: Optional[int] = None
    repo_name: Optional[str] = None

class CIGateResponse(BaseModel):
    passed: bool
    verdict: str
    security_score: int
    security_grade: str
    critical_count: int
    high_count: int
    total_threats: int
    blocking_violations: List[Dict[str, Any]]
    pr_comment_markdown: str
    sarif_report: Dict[str, Any]

@router.post("/gate", response_model=CIGateResponse)
def evaluate_ci_gate(req: CIGateRequest):
    try:
        nodes, edges, detected_fmt = parse_architecture(req.raw_code, req.format)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Architecture parse error: {str(e)}")

    threats = evaluate_stride_rules(nodes, edges)
    attack_paths, score, summary = build_graph_and_find_paths(nodes, edges, threats)
    summary["detected_format"] = detected_fmt

    topo = ArchitectureTopology(
        nodes=nodes,
        edges=edges,
        threats=threats,
        attack_paths=attack_paths,
        security_score=score,
        summary=summary
    )

    # Determine severity ranking
    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }
    threshold = severity_order.get(req.fail_on.upper(), 4)

    blocking = []
    for t in threats:
        sev_rank = severity_order.get(t.severity.value, 1)
        if sev_rank >= threshold:
            blocking.append({
                "id": t.id,
                "title": t.title,
                "severity": t.severity.value,
                "target": t.target_name,
                "category": t.stride_category.value,
                "cvss": t.cvss_score,
                "advice": t.remediation_advice
            })

    passed = (len(blocking) == 0) and (score >= req.min_score)

    verdict_emoji = "✅ PASSED" if passed else "❌ FAILED"
    verdict_desc = "Architecture adheres to security baseline." if passed else f"Blocked by {len(blocking)} violation(s) exceeding '{req.fail_on}' threshold or score below {req.min_score}."

    # Generate PR Comment Markdown
    pr_md = f"""## 🛡️ ThreatForge AI — Security Architecture Gate: {verdict_emoji}

> **Security Score:** **{score}/100** (Grade: **{summary.get("security_grade", "N/A")}**) | **Status:** {verdict_desc}

### 📊 Summary
| Component | Metric |
|---|---|
| **Detected Format** | `{detected_fmt}` |
| **Architectural Nodes** | {len(nodes)} |
| **Interconnects (Data Flows)** | {len(edges)} |
| **Exploitable Attack Paths** | {len(attack_paths)} |
| **Critical Threats** | {summary.get("critical_threats", 0)} |
| **High Threats** | {summary.get("high_threats", 0)} |

"""
    if blocking:
        pr_md += "### ⛔ Blocking Security Violations\n\n"
        pr_md += "| Severity | Threat | Target Node | STRIDE | Remediation |\n"
        pr_md += "|---|---|---|---|---|\n"
        for b in blocking:
            pr_md += f"| **{b['severity']}** | {b['title']} | `{b['target']}` | {b['category']} | {b['advice']} |\n"
        pr_md += "\n> 🚨 **Action Required:** Please apply remediation patches to resolve blocking violations before merging.\n"
    else:
        pr_md += "🎉 **No blocking security violations detected! All cloud resources comply with safety gates.**\n"

    sarif = generate_sarif(topo)

    return CIGateResponse(
        passed=passed,
        verdict=f"{verdict_emoji} - {verdict_desc}",
        security_score=score,
        security_grade=summary.get("security_grade", "F"),
        critical_count=summary.get("critical_threats", 0),
        high_count=summary.get("high_threats", 0),
        total_threats=len(threats),
        blocking_violations=blocking,
        pr_comment_markdown=pr_md,
        sarif_report=sarif
    )

@router.post("/sarif")
def export_sarif_endpoint(topo: ArchitectureTopology):
    return generate_sarif(topo)
