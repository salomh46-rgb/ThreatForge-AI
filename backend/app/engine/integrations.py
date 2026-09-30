import httpx
from typing import Dict, Any, Optional
from app.core.models import ThreatFinding
from app.core.security import validate_webhook_url

def format_jira_issue(threat: ThreatFinding, project_key: str = "SEC") -> Dict[str, Any]:
    description_text = f"""*ThreatForge AI Architecture Security Finding*

*Threat Title:* {threat.title}
*Target Node:* {threat.target_name} ({threat.target_id})
*STRIDE Category:* {threat.stride_category.value}
*CVSS 4.0 Score:* {threat.cvss_score} / 10.0
*Severity:* {threat.severity.value}
*MITRE ATT&CK:* {threat.mitre_technique}
*Blast Radius:* {", ".join(threat.blast_radius_nodes)}

*Description:*
{threat.description}

*Remediation Advice:*
{threat.remediation_advice}

*Suggested Code Patch:*
{{code:diff}}
{threat.code_patch if threat.code_patch else "# No automated code patch available"}
{{code}}
"""
    return {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[ThreatForge-{threat.severity.value}] {threat.title} on {threat.target_name}",
            "description": description_text,
            "issuetype": {"name": "Bug"},
            "priority": {"name": "Highest" if threat.severity.value == "CRITICAL" else "High"},
            "labels": ["security", "threatforge", threat.stride_category.value.lower()]
        }
    }

def format_slack_message(threat: ThreatFinding) -> Dict[str, Any]:
    emoji = "🔴" if threat.severity.value == "CRITICAL" else "🟠"
    return {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Architecture Alert: {threat.title}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* `{threat.severity.value}` (CVSS {threat.cvss_score})"},
                    {"type": "mrkdwn", "text": f"*STRIDE:* `{threat.stride_category.value}`"},
                    {"type": "mrkdwn", "text": f"*Target:* `{threat.target_name}`"},
                    {"type": "mrkdwn", "text": f"*MITRE:* `{threat.mitre_technique}`"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{threat.description}*\n\n💡 *Fix:* {threat.remediation_advice}"
                }
            }
        ]
    }

async def dispatch_webhook(webhook_url: str, payload: Dict[str, Any]) -> bool:
    # Validate against SSRF (checks protocol, allowed domains, private IP blocking)
    validated_url = validate_webhook_url(webhook_url)

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.post(validated_url, json=payload)
            return res.status_code in [200, 201, 204]
    except Exception:
        return False
