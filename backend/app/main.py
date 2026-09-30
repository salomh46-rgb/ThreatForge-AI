from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.analyze import router as analyze_router
from app.api.export import router as export_router
from app.api.ci import router as ci_router
from app.api.compliance import router as compliance_router
from app.api.integrations import router as integrations_router
from app.api.policies import router as policies_router

app = FastAPI(
    title="ThreatForge AI Enterprise API",
    description="Automated STRIDE/MITRE Threat Modeling, CI/CD Gate, Compliance & Custom Policy Engine",
    version="2.0.0"
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(export_router)
app.include_router(ci_router)
app.include_router(compliance_router)
app.include_router(integrations_router)
app.include_router(policies_router)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ThreatForge AI Enterprise Engine",
        "version": "2.0.0",
        "pillars": [
            "CI/CD Quality Gate & GitHub Action",
            "Compliance Matrix (PCI-DSS, ISO 27001, SOC 2, KHM)",
            "Jira/Slack & Risk Acceptance Workflow",
            "Custom Enterprise Policy Engine (OPA/Rego style)"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
