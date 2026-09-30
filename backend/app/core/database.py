import sqlite3
import os
import uuid
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "threatforge.db"

def get_connection():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()

        # 1. Risk Exceptions Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_exceptions (
                id TEXT PRIMARY KEY,
                threat_id TEXT NOT NULL,
                threat_title TEXT NOT NULL,
                target_node TEXT NOT NULL,
                justification TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

        # 2. Custom Corporate Policies Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS custom_policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_zone TEXT NOT NULL,
                rule_condition TEXT NOT NULL,
                severity TEXT NOT NULL,
                remediation_advice TEXT NOT NULL,
                is_enabled INTEGER NOT NULL DEFAULT 1
            )
        """)

        # 3. IMMUTABLE SECURITY AUDIT LOGS Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_audit_logs (
                id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                target TEXT NOT NULL,
                details TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        conn.commit()

# --- Immutable Audit Logger ---
def log_audit_event(event_type: str, actor: str, target: str, details: str):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_audit_logs (id, event_type, actor, target, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            str(uuid.uuid4())[:12],
            event_type,
            actor,
            target,
            details,
            datetime.now().isoformat()
        ))
        conn.commit()

def get_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM security_audit_logs ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]
