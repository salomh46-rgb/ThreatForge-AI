"""
ThreatForge AI - Agent Firewall & Prompt Injection Defense Engine (v2.0)
Sub-millisecond semantic firewall protecting LLMs and AI Agents (Cursor, Claude, Copilot, LangChain)
against Prompt Injection, Jailbreaks, System Prompt Leakage, and Tool Execution Exploits.
"""

import re
import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class FirewallRule(BaseModel):
    id: str
    name: str
    category: str  # prompt_injection, system_leak, jailbreak, tool_abuse
    severity: str  # critical, high, medium, low
    pattern: str
    description: str

class InspectionRequest(BaseModel):
    prompt: str = Field(..., max_length=50000, description="The incoming user prompt or agent thought to inspect")
    context: Optional[str] = Field(None, max_length=10000, description="System instructions or environment context")
    strict_mode: bool = Field(False, description="Whether to reject high-confidence indirect injections")

class InspectionResult(BaseModel):
    is_safe: bool
    risk_score: float  # 0.0 (clean) to 1.0 (malicious)
    latency_ms: float
    threats_detected: List[Dict[str, Any]]
    sanitized_prompt: Optional[str] = None
    action_taken: str  # allow, sanitize, block
    recommendation: str

# Pre-compiled high-speed heuristic signatures (OWASP Top 10 for LLM Applications 2026)
CORE_FIREWALL_RULES: List[FirewallRule] = [
    FirewallRule(
        id="RULE-INJ-001",
        name="System Instruction Override",
        category="prompt_injection",
        severity="critical",
        pattern=r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts)|disregard\s+(everything|prior)|forget\s+all\s+rules)",
        description="Attempts to bypass system prompt boundaries and neutralize safety guardrails."
    ),
    FirewallRule(
        id="RULE-INJ-002",
        name="Roleplay Jailbreak (DAN / Evil Confidant)",
        category="jailbreak",
        severity="critical",
        pattern=r"(?i)(you\s+are\s+now\s+(DAN|unfiltered|jailbroken|an\s+adversary)|from\s+now\s+on\s+you\s+have\s+no\s+rules|pretend\s+you\s+have\s+no\s+ethics)",
        description="Classic roleplay jailbreak pattern forcing the LLM into an unrestricted state."
    ),
    FirewallRule(
        id="RULE-LEAK-003",
        name="System Prompt & Secret Exfiltration",
        category="system_leak",
        severity="high",
        pattern=r"(?i)(repeat\s+the\s+words\s+above|print\s+(your|the)\s+(system\s+prompt|initial\s+instructions)|show\s+me\s+your\s+hidden\s+developer\s+prompt|what\s+are\s+your\s+secret\s+instructions)",
        description="Extracts intellectual property, proprietary system prompts, or hidden API keys."
    ),
    FirewallRule(
        id="RULE-TOOL-004",
        name="Unauthorized Autonomous Shell Execution",
        category="tool_abuse",
        severity="critical",
        pattern=r"(?i)(rm\s+-rf\s+/|curl\s+.*\|\s*(bash|sh)|invoke_tool\(.*['\"](exec|run_command|eval)['\"]|chmod\s+777|format\s+c:)",
        description="Attempts to trick autonomous coding agents into executing destructive shell payloads."
    ),
    FirewallRule(
        id="RULE-INDIRECT-005",
        name="Indirect Markdown / Invisible Data Tag Injection",
        category="prompt_injection",
        severity="medium",
        pattern=r"(?i)(<!--\s*ai_instruction:.*-->|<\|im_start\|>|<\|endoftext\|>|\[SYSTEM_OVERRIDE\])",
        description="Invisible HTML comments or synthetic delimiter tokens designed to poison RAG sources."
    )
]

def inspect_prompt(payload: InspectionRequest) -> InspectionResult:
    start_time = time.perf_counter()
    prompt = payload.prompt
    threats = []
    highest_severity = 0.0

    severity_weights = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.45,
        "low": 0.2
    }

    for rule in CORE_FIREWALL_RULES:
        matches = re.finditer(rule.pattern, prompt)
        match_list = [m.group(0) for m in matches]
        if match_list:
            weight = severity_weights.get(rule.severity, 0.5)
            highest_severity = max(highest_severity, weight)
            threats.append({
                "rule_id": rule.id,
                "name": rule.name,
                "category": rule.category,
                "severity": rule.severity,
                "matches": match_list[:3],
                "description": rule.description
            })

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    # Decision Matrix
    is_safe = len(threats) == 0
    risk_score = round(highest_severity, 2)

    if risk_score >= 0.75:
        action = "block"
        recommendation = "Reject request immediately. High confidence Prompt Injection or Exploit detected."
        sanitized = None
    elif risk_score >= 0.40:
        action = "sanitize" if not payload.strict_mode else "block"
        recommendation = "Strip malicious tokens or wrap prompt inside an isolated XML boundary."
        # Quick sanitization
        sanitized = prompt
        for t in threats:
            for m in t["matches"]:
                sanitized = sanitized.replace(m, "[FILTERED_PAYLOAD]")
    else:
        action = "allow"
        recommendation = "Safe to process by AI Agent or LLM."
        sanitized = prompt

    return InspectionResult(
        is_safe=is_safe,
        risk_score=risk_score,
        latency_ms=round(elapsed_ms, 3),
        threats_detected=threats,
        sanitized_prompt=sanitized,
        action_taken=action,
        recommendation=recommendation
    )
