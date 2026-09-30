export type NodeType =
  | 'internet'
  | 'load_balancer'
  | 'api_gateway'
  | 'microservice'
  | 'database'
  | 'cache'
  | 'storage_bucket'
  | 'auth_service'
  | 'firewall'
  | 'queue'
  | 'generic';

export type TrustZone =
  | 'Public Internet'
  | 'DMZ / Ingress'
  | 'Private App VPC'
  | 'Secure Data Tier'
  | 'Internal Management';

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type StrideCategory =
  | 'Spoofing'
  | 'Tampering'
  | 'Repudiation'
  | 'Information Disclosure'
  | 'Denial of Service'
  | 'Elevation of Privilege';

export interface NodeModel {
  id: string;
  label: string;
  type: NodeType;
  trust_zone: TrustZone;
  is_public: boolean;
  ports: number[];
  environment_vars?: Record<string, string>;
  properties?: Record<string, any>;
  threat_count: number;
  highest_severity?: ThreatSeverity | null;
}

export interface EdgeModel {
  id: string;
  source: string;
  target: string;
  label?: string | null;
  protocol: string;
  is_encrypted: boolean;
  port?: number | null;
  crosses_boundary: boolean;
}

export interface ThreatFinding {
  id: string;
  target_id: string;
  target_name: string;
  stride_category: StrideCategory;
  title: string;
  description: string;
  severity: ThreatSeverity;
  cvss_score: number;
  mitre_technique: string;
  blast_radius_nodes: string[];
  remediation_advice: string;
  code_patch?: string | null;
}

export interface AttackPath {
  id: string;
  name: string;
  entry_node_id: string;
  target_node_id: string;
  path_nodes: string[];
  description: string;
  risk_level: ThreatSeverity;
}

export interface ArchitectureTopology {
  nodes: NodeModel[];
  edges: EdgeModel[];
  threats: ThreatFinding[];
  attack_paths: AttackPath[];
  security_score: number;
  summary: {
    total_nodes: number;
    total_edges: number;
    total_threats: number;
    critical_threats: number;
    high_threats: number;
    medium_threats: number;
    low_threats: number;
    attack_paths_count: number;
    security_grade: string;
    detected_format?: string;
  };
}

export interface PresetSummary {
  id: string;
  title: string;
  description: string;
  format: string;
}
