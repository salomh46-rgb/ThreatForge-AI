from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.analyze import router as analyze_router
from app.api.export import router as export_router

app = FastAPI(
    title="ThreatForge AI API",
    description="Automated STRIDE & MITRE Threat Modeling Engine for Cloud Architects & SecOps",
    version="1.0.0"
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

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ThreatForge AI Engine",
        "version": "1.0.0",
        "supported_formats": ["Terraform HCL", "Docker Compose", "Mermaid Diagram", "Auto"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
