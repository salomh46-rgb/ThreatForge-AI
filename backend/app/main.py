import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import init_db, get_audit_logs
from app.core.security import RequestSizeLimitMiddleware, verify_api_key
from app.engine.custom_policies import seed_default_policies
from app.api.analyze import router as analyze_router
from app.api.export import router as export_router
from app.api.ci import router as ci_router
from app.api.compliance import router as compliance_router
from app.api.integrations import router as integrations_router
from app.api.policies import router as policies_router
from app.api.firewall import router as firewall_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database and default seed data on startup
    init_db()
    seed_default_policies()
    yield

app = FastAPI(
    title="ThreatForge AI Enterprise Hardened API",
    description="Automated STRIDE/MITRE Threat Modeling Engine with SSRF Protection, SQLite Persistence, Immutable Audit Log & Strict CORS",
    version="2.1.0",
    lifespan=lifespan
)

# 1. 1MB Request Payload Limit Middleware (Prevents DoS/Memory exhaustion)
app.add_middleware(RequestSizeLimitMiddleware, max_size_bytes=1_048_576)

# 2. Strict Production CORS Policy (No Wildcard '*')
raw_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000"
)
allowed_origins = [o.strip() for o in raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

# Include API Routers
app.include_router(analyze_router)
app.include_router(export_router)
app.include_router(ci_router)
app.include_router(compliance_router)
app.include_router(integrations_router)
app.include_router(policies_router)
app.include_router(firewall_router)

# Immutable Security Audit Logs Endpoint
@app.get("/api/audit/logs")
def read_audit_logs(limit: int = 100):
    return get_audit_logs(limit)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ThreatForge AI Enterprise Hardened Engine",
        "version": "2.1.0",
        "security_posture": {
            "ssrf_protection": "ACTIVE (Private IP & DNS resolution block)",
            "cors_policy": "STRICT (Explicit whitelisted origins)",
            "payload_limit": "1MB enforced",
            "storage": "Persistent SQLite with Immutable Audit Log",
            "api_key_auth": "Configured (X-API-Key)"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
