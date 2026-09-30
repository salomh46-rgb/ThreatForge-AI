import sys
import argparse
import json
from pathlib import Path
from app.parsers.generic_parser import parse_architecture
from app.engine.stride_rules import evaluate_stride_rules
from app.core.graph import build_graph_and_find_paths
from app.core.models import ArchitectureTopology
from app.engine.sarif import generate_sarif

def main():
    parser = argparse.ArgumentParser(
        prog="threatforge",
        description="ThreatForge AI — Automated Architecture Threat Modeling & CI/CD Security Gate"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan architecture files (.tf, .yml, .mmd)")
    scan_parser.add_argument("file", help="Path to architecture file (e.g. docker-compose.yml or main.tf)")
    scan_parser.add_argument("--format", default="auto", choices=["auto", "compose", "terraform", "mermaid"], help="Source code format")
    scan_parser.add_argument("--fail-on", default="CRITICAL", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Severity threshold that breaks CI")
    scan_parser.add_argument("--min-score", type=int, default=70, help="Minimum security score (0-100) required to pass")
    scan_parser.add_argument("--sarif", help="Path to write SARIF report (e.g. results.sarif)")
    scan_parser.add_argument("--json", action="store_true", help="Output summary in JSON format")

    args = parser.parse_args()

    if args.command == "scan":
        filepath = Path(args.file)
        if not filepath.exists():
            print(f"Error: File '{args.file}' not found.", file=sys.stderr)
            sys.exit(2)

        content = filepath.read_text(encoding="utf-8")
        try:
            nodes, edges, detected_fmt = parse_architecture(content, args.format)
        except Exception as e:
            print(f"Error parsing architecture: {e}", file=sys.stderr)
            sys.exit(2)

        threats = evaluate_stride_rules(nodes, edges)
        attack_paths, score, summary = build_graph_and_find_paths(nodes, edges, threats)

        topo = ArchitectureTopology(
            nodes=nodes,
            edges=edges,
            threats=threats,
            attack_paths=attack_paths,
            security_score=score,
            summary=summary
        )

        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        threshold = severity_order[args.fail_on]

        blocking = [t for t in threats if severity_order.get(t.severity.value, 1) >= threshold]
        passed = (len(blocking) == 0) and (score >= args.min_score)

        if args.sarif:
            sarif_data = generate_sarif(topo)
            Path(args.sarif).write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
            print(f"[+] SARIF report saved to: {args.sarif}")

        if args.json:
            out = {
                "passed": passed,
                "score": score,
                "grade": summary.get("security_grade"),
                "total_threats": len(threats),
                "blocking_threats": len(blocking),
                "critical": summary.get("critical_threats"),
                "high": summary.get("high_threats")
            }
            print(json.dumps(out, indent=2))
        else:
            print("=" * 60)
            print(" 🛡️  THREATFORGE AI ARCHITECTURE SECURITY GATE")
            print("=" * 60)
            print(f" File Scanned:     {filepath.name} ({detected_fmt})")
            print(f" Security Score:   {score}/100 (Grade: {summary.get('security_grade')})")
            print(f" Nodes: {len(nodes)}  |  Flows: {len(edges)}  |  Attack Paths: {len(attack_paths)}")
            print(f" Total Threats:    {len(threats)} (Critical: {summary.get('critical_threats')}, High: {summary.get('high_threats')})")
            print("-" * 60)

            if blocking:
                print(f"⛔ BLOCKING VIOLATIONS (Threshold: {args.fail_on}):")
                for idx, b in enumerate(blocking, 1):
                    print(f" [{idx}] [{b.severity.value}] {b.title}")
                    print(f"     Target: {b.target_name} ({b.target_id}) | Category: {b.stride_category.value}")
                    print(f"     Advice: {b.remediation_advice}")
                    print()

            print("=" * 60)
            if passed:
                print(" ✅ GATE PASSED: Architecture complies with security policy.")
                sys.exit(0)
            else:
                print(f" ❌ GATE FAILED: {len(blocking)} violation(s) violate '{args.fail_on}' threshold (or score < {args.min_score}).")
                sys.exit(1)

if __name__ == "__main__":
    main()
