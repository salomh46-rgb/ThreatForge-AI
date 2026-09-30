from fastapi import APIRouter, HTTPException
from app.core.models import AnalyzeRequest, ArchitectureTopology
from app.parsers.generic_parser import parse_architecture
from app.engine.stride_rules import evaluate_stride_rules
from app.core.graph import build_graph_and_find_paths
from app.api.presets import PRESETS

router = APIRouter(prefix="/api", tags=["Analysis"])

@router.get("/presets")
def get_presets():
    return [
        {"id": k, "title": v["title"], "description": v["description"], "format": v["format"]}
        for k, v in PRESETS.items()
    ]

@router.get("/presets/{preset_id}")
def get_preset_detail(preset_id: str):
    if preset_id not in PRESETS:
        raise HTTPException(status_code=404, detail="Preset not found")
    return PRESETS[preset_id]

@router.post("/analyze", response_model=ArchitectureTopology)
def analyze_architecture(req: AnalyzeRequest):
    try:
        nodes, edges, detected_fmt = parse_architecture(req.raw_code, req.format)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parsing error: {str(e)}")

    if not nodes:
        raise HTTPException(status_code=400, detail="No architectural components could be identified in the provided input.")

    # Run STRIDE evaluation
    threats = evaluate_stride_rules(nodes, edges)

    # Run Attack Path & Score calculation
    attack_paths, score, summary = build_graph_and_find_paths(nodes, edges, threats)
    summary["detected_format"] = detected_fmt

    return ArchitectureTopology(
        nodes=nodes,
        edges=edges,
        threats=threats,
        attack_paths=attack_paths,
        security_score=score,
        summary=summary
    )
