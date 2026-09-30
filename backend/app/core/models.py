from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class NodeType(str, Enum):
    INTERNET = "internet"
    LOAD_BALANCER = "load_balancer"
    API_GATEWAY = "api_gateway"
    MICROSERVICE = "microservice"
    DATABASE = "database"
    CACHE = "cache"
    STORAGE_BUCKET = "storage_bucket"
    AUTH_SERVICE = "auth_service"
    FIREWALL = "firewall"
    QUEUE = "queue"
    GENERIC = "generic"

class TrustZone(str, Enum):
    PUBLIC_INTERNET = "Public Internet"
    DMZ = "DMZ / Ingress"
    PRIVATE_VPC = "Private App VPC"
    DATA_TIER = "Secure Data Tier"
    INTERNAL_SECURE = "Internal Management"

class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class StrideCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

class NodeModel(BaseModel):
    id: str
    label: str
    type: NodeType = NodeType.GENERIC
    trust_zone: TrustZone = TrustZone.PRIVATE_VPC
    is_public: bool = False
    ports: List[int] = Field(default_factory=list)
    environment_vars: Dict[str, str] = Field(default_factory=dict)
    properties: Dict[str, Any] = Field(default_factory=dict)
    threat_count: int = 0
    highest_severity: Optional[ThreatSeverity] = None

class EdgeModel(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = None
    protocol: str = "TCP"
    is_encrypted: bool = True
    port: Optional[int] = None
    crosses_boundary: bool = False

class ThreatFinding(BaseModel):
    id: str
    target_id: str
    target_name: str
    stride_category: StrideCategory
    title: str
    description: str
    severity: ThreatSeverity
    cvss_score: float
    mitre_technique: str
    blast_radius_nodes: List[str] = Field(default_factory=list)
    remediation_advice: str
    code_patch: Optional[str] = None

class AttackPath(BaseModel):
    id: str
    name: str
    entry_node_id: str
    target_node_id: str
    path_nodes: List[str]
    description: str
    risk_level: ThreatSeverity

class ArchitectureTopology(BaseModel):
    nodes: List[NodeModel]
    edges: List[EdgeModel]
    threats: List[ThreatFinding] = Field(default_factory=list)
    attack_paths: List[AttackPath] = Field(default_factory=list)
    security_score: int = 100
    summary: Dict[str, Any] = Field(default_factory=dict)

class AnalyzeRequest(BaseModel):
    format: str = "auto"  # terraform, compose, mermaid, auto
    raw_code: str
    api_key: Optional[str] = None

class RemediationRequest(BaseModel):
    threat_id: str
    target_code: str
    format: str
