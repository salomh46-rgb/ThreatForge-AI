from fastapi import APIRouter, HTTPException
from app.engine.firewall_engine import (
    inspect_prompt,
    InspectionRequest,
    InspectionResult,
    CORE_FIREWALL_RULES
)

router = APIRouter(prefix="/api/firewall", tags=["AI Agent Security & Prompt Injection Firewall"])

@router.post("/inspect", response_model=InspectionResult)
def inspect_incoming_prompt(request: InspectionRequest):
    """
    Inspects an incoming prompt or agent tool call for Prompt Injection, Jailbreaks, and Unauthorized Execution.
    Returns sub-millisecond risk scores, detected threat rules, and recommended actions.
    """
    try:
        return inspect_prompt(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Firewall inspection error: {str(e)}")

@router.get("/rules")
def list_active_rules():
    """Returns the list of OWASP LLM 2026 pre-compiled firewall heuristic signatures."""
    return {
        "total_rules": len(CORE_FIREWALL_RULES),
        "rules": [rule.model_dump() for rule in CORE_FIREWALL_RULES]
    }
