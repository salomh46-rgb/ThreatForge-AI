import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from pydantic import BaseModel, Field
from app.core.database import get_connection, log_audit_event

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

def create_risk_exception(
    threat_id: str,
    threat_title: str,
    target_node: str,
    justification: str,
    approved_by: str,
    days_valid: int = 90
) -> RiskException:
    exc_id = str(uuid.uuid4())[:8]
    created = datetime.now().isoformat()
    expires = (datetime.now() + timedelta(days=days_valid)).strftime("%Y-%m-%d")

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO risk_exceptions (id, threat_id, threat_title, target_node, justification, approved_by, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
        """, (exc_id, threat_id, threat_title, target_node, justification, approved_by, created, expires))
        conn.commit()

    # Immutable Audit Log
    log_audit_event(
        event_type="RISK_EXCEPTION_CREATED",
        actor=approved_by,
        target=f"{target_node} ({threat_id})",
        details=f"Risk signed off. Justification: {justification}. Valid until {expires}"
    )

    return RiskException(
        id=exc_id,
        threat_id=threat_id,
        threat_title=threat_title,
        target_node=target_node,
        justification=justification,
        approved_by=approved_by,
        status="ACTIVE",
        created_at=created,
        expires_at=expires
    )

def list_risk_exceptions() -> List[RiskException]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM risk_exceptions ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [RiskException(**dict(row)) for row in rows]

def revoke_risk_exception(exception_id: str, actor: str = "CISO Admin") -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE risk_exceptions SET status = 'REVOKED' WHERE id = ?", (exception_id,))
        affected = cursor.rowcount
        conn.commit()

    if affected > 0:
        log_audit_event(
            event_type="RISK_EXCEPTION_REVOKED",
            actor=actor,
            target=exception_id,
            details=f"Risk exception {exception_id} revoked manually by security admin."
        )
        return True
    return False

def is_threat_excepted(threat_id: str) -> Optional[RiskException]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM risk_exceptions WHERE threat_id = ? AND status = 'ACTIVE'", (threat_id,))
        row = cursor.fetchone()
        if row:
            return RiskException(**dict(row))
    return None
