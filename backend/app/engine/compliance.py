from typing import List, Dict, Any
from pydantic import BaseModel, Field
from app.core.models import ThreatFinding, StrideCategory, ThreatSeverity

class ControlViolation(BaseModel):
    control_id: str
    control_name: str
    description: str
    violation_threat_id: str
    threat_title: str
    severity: str
    remediation: str

class FrameworkScorecard(BaseModel):
    framework_id: str
    framework_name: str
    category: str
    total_controls: int
    passing_controls: int
    failing_controls: int
    compliance_percentage: int
    status: str  # COMPLIANT, WARNING, NON_COMPLIANT
    violations: List[ControlViolation] = Field(default_factory=list)

class ComplianceAuditReport(BaseModel):
    frameworks: Dict[str, FrameworkScorecard]
    overall_compliance: int
    summary_verdict: str

# Defined Enterprise Compliance Frameworks
FRAMEWORK_DEFS = {
    "pci_dss": {
        "name": "PCI-DSS v4.0 (Payment Card Industry)",
        "category": "Global Fintech & Payments",
        "controls": {
            "req_1_3": {
                "name": "Requirement 1.3 - Network Segregation & DMZ",
                "desc": "Prohibit direct public internet access to cardholder data environments (Databases & Caches).",
                "triggers": [StrideCategory.INFO_DISCLOSURE, StrideCategory.ELEVATION_OF_PRIVILEGE]
            },
            "req_4_1": {
                "name": "Requirement 4.1 - In-Transit Cryptography",
                "desc": "Protect cardholder data with strong TLS cryptography across open, public, or internal cross-zone networks.",
                "triggers": [StrideCategory.TAMPERING]
            },
            "req_6_4": {
                "name": "Requirement 6.4 - Web Application Firewall",
                "desc": "Deploy an automated technical solution (WAF) that continually detects and prevents web-based attacks.",
                "triggers": [StrideCategory.DENIAL_OF_SERVICE]
            },
            "req_10_2": {
                "name": "Requirement 10.2 - Audit Logging",
                "desc": "Implement automated audit trails for all system components to record security events.",
                "triggers": [StrideCategory.REPUDIATION]
            }
        }
    },

    "iso_27001": {
        "name": "ISO/IEC 27001:2022",
        "category": "International Information Security Standard",
        "controls": {
            "a_8_20": {
                "name": "Control A.8.20 - Network Segregation",
                "desc": "Groups of information services, users and systems shall be segregated in networks.",
                "triggers": [StrideCategory.INFO_DISCLOSURE, StrideCategory.SPOOFING]
            },
            "a_8_24": {
                "name": "Control A.8.24 - Use of Cryptography",
                "desc": "Rules for the effective use of cryptography, including crypto-key management, shall be implemented.",
                "triggers": [StrideCategory.TAMPERING]
            },
            "a_8_26": {
                "name": "Control A.8.26 - Application Security",
                "desc": "Information security requirements shall be identified and addressed when developing applications.",
                "triggers": [StrideCategory.ELEVATION_OF_PRIVILEGE, StrideCategory.SPOOFING]
            },
            "a_8_15": {
                "name": "Control A.8.15 - Logging",
                "desc": "Logs that record activities, exceptions, faults and other security events shall be produced and kept.",
                "triggers": [StrideCategory.REPUDIATION]
            }
        }
    },

    "soc_2": {
        "name": "SOC 2 Type II (Trust Services Criteria)",
        "category": "SaaS & Cloud Security Compliance",
        "controls": {
            "cc_6_1": {
                "name": "CC6.1 - Logical Access Controls",
                "desc": "The entity restricts logical access to confidential databases and infrastructure components.",
                "triggers": [StrideCategory.INFO_DISCLOSURE, StrideCategory.ELEVATION_OF_PRIVILEGE]
            },
            "cc_6_6": {
                "name": "CC6.6 - Boundary Protection & DDoS Defense",
                "desc": "The entity implements perimeter boundary protections to prevent unauthorized or malicious traffic.",
                "triggers": [StrideCategory.DENIAL_OF_SERVICE]
            },
            "cc_6_7": {
                "name": "CC6.7 - Data Transmission Encryption",
                "desc": "The entity encrypts customer data during transmission over internal and external communication networks.",
                "triggers": [StrideCategory.TAMPERING]
            }
        }
    },

    "khm_uz": {
        "name": "O'zbekiston KHM & MB Kiberxavfsizlik Me'yorlari",
        "category": "Milliy Qonunchilik va Davlat Standarti",
        "controls": {
            "khm_01": {
                "name": "KHM-01: Baza va Saqlash Tizimlarini Izolyatsiyalash",
                "desc": "Davlat va moliya axborot tizimlarida ma'lumotlar bazasi to'g'ridan-to'g'ri tashqi ommaviy tarmoqqa chiqmasligi shart.",
                "triggers": [StrideCategory.INFO_DISCLOSURE]
            },
            "khm_02": {
                "name": "KHM-02: Kriptografik Himoyalangan Kanallar (TLS)",
                "desc": "Axborot almashinuvi paytida shaxsga doir ma'lumotlar faqat sertifikatlangan TLS kanallari orqali uzatilishi shart.",
                "triggers": [StrideCategory.TAMPERING]
            },
            "khm_03": {
                "name": "KHM-03: Kiberhujumlarni Qaytarish (WAF/DDoS)",
                "desc": "Ommaviy davlat va bank xizmatlari kirish nuqtalarida WAF va oqimni filtrlash vositalari o'rnatilishi shart.",
                "triggers": [StrideCategory.DENIAL_OF_SERVICE]
            },
            "khm_04": {
                "name": "KHM-04: Markazlashgan Autentifikatsiya va RBAC",
                "desc": "Tizim funksiyalariga kirishda yagona identifikatsiya va ruxsatlar boshqaruvi bo'lishi shart.",
                "triggers": [StrideCategory.SPOOFING, StrideCategory.ELEVATION_OF_PRIVILEGE]
            }
        }
    }
}

def evaluate_compliance(threats: List[ThreatFinding]) -> ComplianceAuditReport:
    framework_results: Dict[str, FrameworkScorecard] = {}
    total_percent_sum = 0

    for fid, fdef in FRAMEWORK_DEFS.items():
        controls = fdef["controls"]
        total_ctrls = len(controls)
        violations: List[ControlViolation] = []

        for cid, cdef in controls.items():
            matching_threats = [t for t in threats if t.stride_category in cdef["triggers"]]
            for mt in matching_threats:
                violations.append(ControlViolation(
                    control_id=cid,
                    control_name=cdef["name"],
                    description=cdef["desc"],
                    violation_threat_id=mt.id,
                    threat_title=mt.title,
                    severity=mt.severity.value,
                    remediation=mt.remediation_advice
                ))

        # Distinct failed controls
        failed_control_ids = set(v.control_id for v in violations)
        failing_count = len(failed_control_ids)
        passing_count = max(0, total_ctrls - failing_count)
        pct = int((passing_count / total_ctrls) * 100)
        total_percent_sum += pct

        status = "COMPLIANT" if pct == 100 else ("WARNING" if pct >= 70 else "NON_COMPLIANT")

        framework_results[fid] = FrameworkScorecard(
            framework_id=fid,
            framework_name=fdef["name"],
            category=fdef["category"],
            total_controls=total_ctrls,
            passing_controls=passing_count,
            failing_controls=failing_count,
            compliance_percentage=pct,
            status=status,
            violations=violations
        )

    avg_pct = int(total_percent_sum / len(FRAMEWORK_DEFS))
    summary = "Audit Ready (Fully Compliant)" if avg_pct >= 95 else ("Action Required (Moderate Gap)" if avg_pct >= 70 else "Critical Non-Compliance (Audit Failed)")

    return ComplianceAuditReport(
        frameworks=framework_results,
        overall_compliance=avg_pct,
        summary_verdict=summary
    )
