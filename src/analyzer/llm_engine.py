import json
import os
import requests
from pathlib import Path
from src.parser.code_parser import CodeSnippet

OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:7b"
TAXONOMY_DIR = Path(__file__).parent.parent.parent / "docs" / "taxonomy"

VALID_CWES = {
    "CWE-311", "CWE-326", "CWE-327", "CWE-328",
    "CWE-329", "CWE-330", "CWE-347", "CWE-798", "CWE-916"
}
VALID_SEVERITIES  = {"CRITICAL", "HIGH", "WARNING", "NONE"}
VALID_CONFIDENCES = {"high", "medium", "low"}


def _load_taxonomy_summary() -> str:
    """Load the quick reference table from the taxonomy README."""
    readme = TAXONOMY_DIR / "README.md"
    if not readme.exists():
        return ""
    text = readme.read_text(encoding="utf-8")
    start = text.find("## Quick reference")
    end   = text.find("\n---", start)
    if start == -1:
        return text[:3000]
    return text[start:end if end != -1 else start + 3000]


def _load_cwe_rules() -> str:
    """Load detection logic sections from all 9 CWE files."""
    rules = []
    for cwe_file in sorted(TAXONOMY_DIR.glob("CWE-*.md")):
        text = cwe_file.read_text(encoding="utf-8")
        start = text.find("## Detection logic")
        end   = text.find("\n## ", start + 1)
        if start != -1:
            section = text[start:end if end != -1 else start + 1500]
            rules.append(f"### {cwe_file.stem}\n{section}")
    return "\n\n".join(rules)


def _build_system_prompt() -> str:
    taxonomy_summary = _load_taxonomy_summary()
    cwe_rules        = _load_cwe_rules()

    return f"""You are a security expert specializing in cryptographic vulnerability detection in Java and Kotlin Android source code for payment terminals.

## Your task
Analyze the provided code snippet and identify any cryptographic vulnerabilities.

## Company context
- 3DES used in bank communication classes → flag as WARNING (bank mandate), not CRITICAL
- 3DES used anywhere else → CRITICAL
- RSA keys below 2048 bits → CRITICAL (company uses RSA for backend)
- JKS KeyStore operations → do NOT flag as password hashing vulnerabilities
- Android KeyStore usage → safe, do not flag

## Detection rules
{cwe_rules}

## Quick reference
{taxonomy_summary}

## CWE classification rules (CRITICAL — apply before deciding any CWE)
- Hardcoded string literal or byte array used directly as a key → CWE-798, NOT CWE-327
- Wrong algorithm (DES, RC4, MD5 for passwords, AES/ECB) → CWE-327
- Key derived from user input, method parameter, or config file → NOT a vulnerability
- Key retrieved from Android KeyStore → NOT a vulnerability
- Key generated fresh with KeyGenerator or KeyPairGenerator → NOT a vulnerability
- Method named good1, good2, goodG2B, goodB2G → these are secure implementations, do NOT flag them
- If a variable is initialized to empty string "" or null and then reassigned from user input or external source, it is NOT hardcoded — track the final value, not the initialization

## Prompt rules (IMPORTANT)
1. First, list every JCA/crypto API call you see in the code (chain-of-thought)
2. For each API call, identify ALL potential misuses — not just the most obvious one
3. Base analysis ONLY on actual code behavior — NOT on variable or method names alone
4. If a key, IV, password, or salt comes from a parameter or external source — do NOT assume it is hardcoded
5. Only flag what you can see directly in this snippet — do not speculate about other methods
6. If in doubt between two CWEs, apply the CWE classification rules above to decide

## Output format
Respond ONLY with a valid JSON array. No explanation, no markdown, no preamble.
Each finding must follow this exact schema:
{{
  "cwe_id": "CWE-XXX",
  "severity": "CRITICAL|HIGH|WARNING|NONE",
  "confidence": "high|medium|low",
  "explanation": "Clear explanation of the vulnerability",
  "fix_code": "Corrected replacement code snippet",
  "line_hint": <integer line number within the snippet where the issue occurs>
}}

If no vulnerability is found, return an empty array: []
Return a JSON array even if there is only one finding.
"""


def _build_user_prompt(snippet: CodeSnippet) -> str:
    return f"""File: {snippet.file_path}
Class: {snippet.context}
Method: {snippet.method_name}
Language: {snippet.language}
Lines: {snippet.start_line}-{snippet.end_line}

Analyze the following code:

```{snippet.language}
{snippet.code}
```
"""


def _validate_finding(finding: dict) -> bool:
    if not isinstance(finding, dict):
        return False
    if finding.get("cwe_id") not in VALID_CWES:
        return False
    if finding.get("severity") not in VALID_SEVERITIES:
        return False
    if finding.get("confidence") not in VALID_CONFIDENCES:
        return False
    return True


def _call_ollama(system_prompt: str, user_prompt: str) -> str:
    payload = {
        "model":  OLLAMA_MODEL,
        "prompt": f"<|system|>\n{system_prompt}\n<|user|>\n{user_prompt}\n<|assistant|>",
        "stream": False,
        "options": {
            "temperature": 0.0,
            "top_p":       0.9,
            "top_k":       20,
        }
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        response.raise_for_status()
        return response.json().get("response", "")
    except requests.exceptions.ConnectionError:
        raise RuntimeError("Ollama is not running. Start it with: ollama serve")
    except requests.exceptions.Timeout:
        raise RuntimeError("Ollama timed out — model may be loading, try again")


def _parse_response(raw: str) -> list:
    """Extract and validate JSON array from model response."""
    raw = raw.strip()

    # Strip markdown code fences if present
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

    # Find JSON array boundaries
    start = raw.find("[")
    end   = raw.rfind("]")
    if start == -1 or end == -1:
        return []

    try:
        findings = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        return []

    if not isinstance(findings, list):
        return []

    return [f for f in findings if _validate_finding(f)]


# Cache system prompt — loaded once per session
_SYSTEM_PROMPT = None

def analyze_snippet(snippet: CodeSnippet) -> list:
    """
    Analyze a single code snippet for cryptographic vulnerabilities.
    Returns a list of finding dicts, empty if no vulnerabilities found.
    """
    global _SYSTEM_PROMPT
    if _SYSTEM_PROMPT is None:
        _SYSTEM_PROMPT = _build_system_prompt()

    user_prompt = _build_user_prompt(snippet)
    raw         = _call_ollama(_SYSTEM_PROMPT, user_prompt)
    findings    = _parse_response(raw)

    # Enrich findings with file location
    for f in findings:
        f["file"]       = snippet.file_path
        f["start_line"] = snippet.start_line
        f["method"]     = snippet.method_name

    return findings


def analyze_file(file_path: str) -> list:
    from src.parser.code_parser import extract_snippets_from_file
    snippets = extract_snippets_from_file(file_path)
    all_findings = []
    for snippet in snippets:
        findings = analyze_snippet(snippet)
        all_findings.extend(findings)
    return all_findings


def analyze_directory(dir_path: str) -> list:
    from src.parser.code_parser import extract_snippets_from_dir
    snippets = extract_snippets_from_dir(dir_path)
    all_findings = []
    total = len(snippets)
    for i, snippet in enumerate(snippets, 1):
        print(f"  [{i}/{total}] Analyzing {snippet.context}.{snippet.method_name}...")
        findings = analyze_snippet(snippet)
        if findings:
            print(f"    → {len(findings)} finding(s)")
        all_findings.extend(findings)
    return all_findings
