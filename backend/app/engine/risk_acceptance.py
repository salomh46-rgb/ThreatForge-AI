import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pydantic import BaseModel, Field

class RiskException(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    threat_id: str
    threat_title: str
    target_node: str
    justification: str
    approved_by: str
    status: str = "ACTIVE"  # ACTIVE, EXPIRED, REVOKED
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    expires_at: str

# In-Memory store for active exceptions
_EXCEPTIONS_STORE: Dict[str, RiskException] = {}

def create_risk_exception(
    threat_id: str,
    threat_title: str,
    target_node: str,
    justification: str,
    approved_by: str,
    days_valid: int = 90
) -> RiskException:
    expires = (datetime.now() + timedelta(days=days_valid)).strftime("%Y-%m-%d")
    exception = RiskException(
        threat_id=threat_id,
        threat_title=threat_title,
        target_node=target_node,
        justification=justification,
        approved_by=approved_by,
        expires_at=expires
    )
    _EXCEPTIONS_STORE[exception.id] = exception
    return exception

def list_risk_exceptions() -> List[RiskException]:
    return list(_EXCEPTIONS_STORE.values())

def revoke_risk_exception(exception_id: str) -> bool:
    if exception_id in _EXCEPTIONS_STORE:
        _EXCEPTIONS_STORE[exception_id].status = "REVOKED"
        return True
    return False

def is_threat_excepted(threat_id: str) -> Optional[RiskException]:
    for exc in _EXCEPTIONS_STORE.values():
        if exc.threat_id == threat_id and exc.status == "ACTIVE":
            return exc
    return None
