from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from app.engine.custom_policies import (
    CustomPolicy, list_custom_policies, add_custom_policy, remove_custom_policy, evaluate_custom_policies
)
from app.parsers.generic_parser import parse_architecture
from app.core.models import ThreatFinding

router = APIRouter(prefix="/api/policies", tags=["Custom Enterprise Policies"])

class EvaluatePoliciesRequest(BaseModel):
    raw_code: str
    format: str = "auto"

@router.get("", response_model=List[CustomPolicy])
def get_policies():
    return list_custom_policies()

@router.post("", response_model=CustomPolicy)
def create_policy(policy: CustomPolicy):
    return add_custom_policy(policy)

@router.delete("/{policy_id}")
def delete_policy(policy_id: str):
    success = remove_custom_policy(policy_id)
    if not success:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"status": "deleted", "policy_id": policy_id}

@router.post("/evaluate", response_model=List[ThreatFinding])
def evaluate_policies_endpoint(req: EvaluatePoliciesRequest):
    try:
        nodes, edges, _ = parse_architecture(req.raw_code, req.format)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return evaluate_custom_policies(nodes, edges)
