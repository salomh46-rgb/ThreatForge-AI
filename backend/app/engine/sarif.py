from typing import Dict, Any
from app.core.models import ArchitectureTopology, ThreatSeverity

def generate_sarif(topology: ArchitectureTopology) -> Dict[str, Any]:
    rules = []
    results = []

    # Map severity to SARIF levels
    def map_level(sev: ThreatSeverity) -> str:
        if sev in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            return "error"
        if sev == ThreatSeverity.MEDIUM:
            return "warning"
        return "note"

    seen_rules = set()

    for threat in topology.threats:
        rule_id = threat.mitre_technique.split(" ")[0].replace(".", "_")
        if not rule_id or rule_id == "T1190":
            rule_id = f"TF_{threat.stride_category.value.upper().replace(' ', '_')}_{threat.id[:8]}"

        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": threat.title,
                "shortDescription": {"text": threat.title},
                "fullDescription": {"text": threat.description},
                "defaultConfiguration": {
                    "level": map_level(threat.severity)
                },
                "properties": {
                    "tags": [
                        "security",
                        "architecture",
                        threat.stride_category.value,
                        threat.mitre_technique
                    ],
                    "precision": "high",
                    "security-severity": str(threat.cvss_score)
                }
            })

        results.append({
            "ruleId": rule_id,
            "level": map_level(threat.severity),
            "message": {
                "text": f"[{threat.severity.value}] {threat.title} on '{threat.target_name}': {threat.remediation_advice}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": threat.target_id
                        },
                        "region": {
                            "startLine": 1
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": threat.target_name,
                            "kind": "architectural_node"
                        }
                    ]
                }
            ]
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ThreatForge AI",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/salomh46-rgb/ThreatForge-AI",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    }
