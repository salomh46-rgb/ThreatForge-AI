from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from app.core.models import ThreatFinding
from app.engine.integrations import format_jira_issue, format_slack_message, dispatch_webhook
from app.engine.risk_acceptance import (
    create_risk_exception, list_risk_exceptions, revoke_risk_exception, RiskException
)

router = APIRouter(prefix="/api/integrations", tags=["Enterprise Integrations & Risk Exceptions"])

class JiraPreviewRequest(BaseModel):
    threat: ThreatFinding
    project_key: str = "SEC"

class WebhookDispatchRequest(BaseModel):
    webhook_url: str
    threat: ThreatFinding

class AcceptRiskRequest(BaseModel):
    threat_id: str
    threat_title: str
    target_node: str
    justification: str
    approved_by: str
    days_valid: int = 90

@router.post("/jira/preview")
def preview_jira_issue(req: JiraPreviewRequest):
    return format_jira_issue(req.threat, req.project_key)

@router.post("/slack/dispatch")
async def dispatch_slack_alert(req: WebhookDispatchRequest):
    payload = format_slack_message(req.threat)
    success = await dispatch_webhook(req.webhook_url, payload)
    return {"success": success, "payload": payload}

# Risk Acceptance API
@router.post("/risk/accept", response_model=RiskException)
def accept_risk(req: AcceptRiskRequest):
    if not req.justification.strip() or not req.approved_by.strip():
        raise HTTPException(status_code=400, detail="Justification and approver name are required for CISO audit.")
    return create_risk_exception(
        threat_id=req.threat_id,
        threat_title=req.threat_title,
        target_node=req.target_node,
        justification=req.justification,
        approved_by=req.approved_by,
        days_valid=req.days_valid
    )

@router.get("/risk/exceptions", response_model=List[RiskException])
def get_exceptions():
    return list_risk_exceptions()

@router.delete("/risk/exceptions/{exception_id}")
def delete_exception(exception_id: str):
    revoked = revoke_risk_exception(exception_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Exception not found")
    return {"status": "revoked", "exception_id": exception_id}
