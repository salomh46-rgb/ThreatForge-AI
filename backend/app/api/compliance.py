from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.parsers.generic_parser import parse_architecture
from app.engine.stride_rules import evaluate_stride_rules
from app.engine.compliance import evaluate_compliance, ComplianceAuditReport, FRAMEWORK_DEFS

router = APIRouter(prefix="/api/compliance", tags=["Compliance Engine"])

class ComplianceAuditRequest(BaseModel):
    raw_code: str
    format: str = "auto"

@router.get("/frameworks")
def list_frameworks():
    return [
        {
            "id": k,
            "name": v["name"],
            "category": v["category"],
            "controls_count": len(v["controls"])
        }
        for k, v in FRAMEWORK_DEFS.items()
    ]

@router.post("/audit", response_model=ComplianceAuditReport)
def run_compliance_audit(req: ComplianceAuditRequest):
    try:
        nodes, edges, _ = parse_architecture(req.raw_code, req.format)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Architecture parse error: {str(e)}")

    threats = evaluate_stride_rules(nodes, edges)
    report = evaluate_compliance(threats)
    return report
