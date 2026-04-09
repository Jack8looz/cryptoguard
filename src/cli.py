import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser.code_parser import extract_snippets_from_file, extract_snippets_from_dir
from src.analyzer.llm_engine import analyze_snippet

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "NONE": 3}

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "WARNING":  "\033[94m",  # blue
    "NONE":     "\033[92m",  # green
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def color(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def print_banner():
    print(f"""
{BOLD}╔══════════════════════════════════════╗
║         CryptoGuard v0.1.0           ║
║  AI-Based Cryptographic SAST Tool    ║
╚══════════════════════════════════════╝{RESET}
""")


def print_finding(f: dict, index: int):
    sev  = f.get("severity", "UNKNOWN")
    cwe  = f.get("cwe_id", "?")
    conf = f.get("confidence", "?")
    file = f.get("file", "?")
    line = f.get("start_line", "?")
    meth = f.get("method", "?")
    expl = f.get("explanation", "")
    fix  = f.get("fix_code", "")

    print(f"  {color(f'[{sev}]', sev)} {BOLD}{cwe}{RESET} — {file}:{line} ({meth})")
    print(f"  Confidence : {conf}")
    print(f"  Explanation: {expl}")
    if fix:
        print(f"  Fix        : {fix[:200]}")
    print()


def print_summary(findings: list, total_snippets: int):
    counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0}
    for f in findings:
        sev = f.get("severity", "")
        if sev in counts:
            counts[sev] += 1

    print(f"{BOLD}── Summary ──────────────────────────────{RESET}")
    print(f"  Snippets analyzed : {total_snippets}")
    print(f"  Findings          : {len(findings)}")
    print(f"  {color('CRITICAL', 'CRITICAL')}          : {counts['CRITICAL']}")
    print(f"  {color('HIGH', 'HIGH')}              : {counts['HIGH']}")
    print(f"  {color('WARNING', 'WARNING')}           : {counts['WARNING']}")
    print()

    if counts["CRITICAL"] > 0:
        print(color("  ✖ CRITICAL vulnerabilities found — fix before deployment", "CRITICAL"))
    elif counts["HIGH"] > 0:
        print(color("  ⚠ HIGH severity findings — review recommended", "HIGH"))
    else:
        print("\033[92m  ✔ No critical findings\033[0m")
    print()


def run_analysis(target: str, severity_filter: str, output_json: str):
    print_banner()

    # Collect snippets
    if os.path.isfile(target):
        print(f"  Scanning file: {target}")
        snippets = extract_snippets_from_file(target)
    elif os.path.isdir(target):
        print(f"  Scanning directory: {target}")
        snippets = extract_snippets_from_dir(target)
    else:
        print(f"  Error: {target} is not a valid file or directory")
        sys.exit(1)

    if not snippets:
        print("  No crypto-relevant code found in target.")
        sys.exit(0)

    print(f"  Found {len(snippets)} crypto-relevant snippet(s)\n")

    # Analyze each snippet
    all_findings = []
    total = len(snippets)
    for i, snippet in enumerate(snippets, 1):
        print(f"  [{i}/{total}] {snippet.context}.{snippet.method_name} "
              f"({snippet.file_path.split('/')[-1]}:{snippet.start_line})")
        findings = analyze_snippet(snippet)
        if findings:
            print(f"         → {len(findings)} finding(s)")
        all_findings.extend(findings)

    print()

    # Filter by severity
    min_level = SEVERITY_ORDER.get(severity_filter.upper(), 1)
    filtered  = [
        f for f in all_findings
        if SEVERITY_ORDER.get(f.get("severity", "NONE"), 3) <= min_level
    ]

    # Sort by severity
    filtered.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity", "NONE"), 3))

    # Print findings
    if filtered:
        print(f"{BOLD}── Findings ─────────────────────────────{RESET}\n")
        for i, f in enumerate(filtered, 1):
            print_finding(f, i)
    else:
        print("  No findings match the severity filter.\n")

    # Print summary
    print_summary(all_findings, total)

    # JSON output
    if output_json:
        with open(output_json, "w") as fp:
            json.dump(all_findings, fp, indent=2)
        print(f"  JSON report saved to: {output_json}")

    # Exit code — 1 if CRITICAL findings exist (for CI/CD)
    critical_count = sum(
        1 for f in all_findings if f.get("severity") == "CRITICAL"
    )
    sys.exit(1 if critical_count > 0 else 0)


def main():
    parser = argparse.ArgumentParser(
        prog="cryptoguard",
        description="AI-based cryptographic vulnerability detection for Java/Kotlin"
    )
    subparsers = parser.add_subparsers(dest="command")

    analyze = subparsers.add_parser("analyze", help="Analyze source code")
    group   = analyze.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="Path to a single Java or Kotlin file")
    group.add_argument("--dir",  "-d", help="Path to a directory to scan recursively")
    analyze.add_argument(
        "--severity", "-s",
        default="HIGH",
        choices=["CRITICAL", "HIGH", "WARNING"],
        help="Minimum severity to report (default: HIGH)"
    )
    analyze.add_argument(
        "--output", "-o",
        default=None,
        help="Save findings to a JSON file"
    )

    args = parser.parse_args()

    if args.command == "analyze":
        target = args.file or args.dir
        run_analysis(target, args.severity, args.output)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()