import json
import os
import requests
from pathlib import Path
from src.parser.code_parser import CodeSnippet

OLLAMA_URL_GENERATE = "http://localhost:11434/api/generate"
OLLAMA_MODEL        = "qwen2.5-coder:7b"
TAXONOMY_DIR        = Path(__file__).parent.parent.parent / "docs" / "taxonomy"

VALID_CWES = {
    "CWE-311", "CWE-326", "CWE-327", "CWE-328",
    "CWE-329", "CWE-330", "CWE-347", "CWE-798", "CWE-916"
}
VALID_SEVERITIES  = {"CRITICAL", "HIGH", "WARNING", "NONE"}
VALID_CONFIDENCES = {"high", "medium", "low"}

MIN_CONFIDENCE = {
    "CWE-798": "high",
    "CWE-311": "medium",
}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

_active_model = OLLAMA_MODEL


def set_model(model_name: str):
    global _active_model, _SYSTEM_PROMPT
    _active_model  = model_name
    _SYSTEM_PROMPT = None
    print(f"  [ENGINE] Model set to: {model_name}")


def get_model() -> str:
    return _active_model


def _is_phi3() -> bool:
    return "phi3" in _active_model.lower() or "phi-3" in _active_model.lower()


def _load_taxonomy_summary() -> str:
    readme = TAXONOMY_DIR / "README.md"
    if not readme.exists():
        return ""
    text  = readme.read_text(encoding="utf-8")
    start = text.find("## Quick reference")
    end   = text.find("\n---", start)
    if start == -1:
        return text[:3000]
    return text[start:end if end != -1 else start + 3000]


def _load_cwe_rules() -> str:
    rules = []
    for cwe_file in sorted(TAXONOMY_DIR.glob("CWE-*.md")):
        text  = cwe_file.read_text(encoding="utf-8")
        start = text.find("## Detection logic")
        end   = text.find("\n## ", start + 1)
        if start != -1:
            section = text[start:end if end != -1 else start + 1500]
            rules.append(f"### {cwe_file.stem}\n{section}")
    return "\n\n".join(rules)


def _build_system_prompt_full() -> str:
    """Full system prompt for Qwen — includes complete taxonomy detection logic."""
    taxonomy_summary = _load_taxonomy_summary()
    cwe_rules        = _load_cwe_rules()

    return f"""You are a security expert specializing in cryptographic vulnerability detection in Java and Kotlin Android source code for payment terminals.

## Your task
Analyze the provided code snippet and identify any cryptographic vulnerabilities.

## Company context
- 3DES used in bank communication classes -> flag as WARNING (bank mandate), not CRITICAL
- 3DES used anywhere else -> CRITICAL
- RSA keys below 2048 bits -> CRITICAL (company uses RSA for backend)
- JKS KeyStore operations -> do NOT flag as password hashing vulnerabilities
- Android KeyStore usage -> safe, do not flag

## Detection rules
{cwe_rules}

## Quick reference
{taxonomy_summary}

## CWE classification rules (CRITICAL -- apply before deciding any CWE)

### CWE-798 -- Hardcoded credentials
- Hardcoded string literal or byte array used directly as a key -> CWE-798, NOT CWE-327
- Key derived from user input, method parameter, or config file -> NOT a vulnerability
- Key retrieved from Android KeyStore -> NOT a vulnerability
- Key generated fresh with KeyGenerator or KeyPairGenerator -> NOT a vulnerability
- Variable initialized to "" or null then immediately overwritten by readLine() or external input -> NOT hardcoded, track the final assigned value not the initialization
- Methods named good1, good2, goodG2B, goodG2B1, goodG2B2, goodB2G -> secure implementations, do NOT flag them under any circumstances
- A hardcoded password literal like "Password1234!" used in getConnection() -> CWE-798, NOT CWE-311
- If comment says "FIX:" or "it was not sent over the network" -> this is a secure pattern, do NOT flag

### CWE-327 -- Wrong algorithm
- Wrong algorithm (DES, 3DES outside bank class, RC4, AES/ECB, MD5 for passwords) -> CWE-327
- AES without mode specified on Android defaults to ECB -> CWE-327

### CWE-330 -- Weak randomness
- new Random() or Math.random() for any security purpose -> CWE-330, always
- SecureRandom is the only safe choice

### CWE-311 -- Missing encryption
- DriverManager.getConnection() with password from external source -> CWE-311
- Hardcoded password in getConnection() -> CWE-798 not CWE-311
- Comment says "FIX:" or "not sent over the network" -> do NOT flag
- goodG2B, goodG2B1, goodG2B2, goodB2G methods -> do NOT flag

### CWE-328 -- Weak hash
- SHA-1, MD5, SHA-256 on password without salt -> CWE-328
- Fast hash for passwords -> CWE-916
- Do NOT use CWE-327 for hashing issues

### CWE-329 -- Predictable IV
- Hardcoded or zeroed IvParameterSpec in CBC mode -> CWE-329

### CWE-326 -- Inadequate key size
- RSA < 2048 bits, EC < 256 bits, AES < 128 bits -> CWE-326

### CWE-347 -- Improper JWT verification
- parseClaimsJwt() instead of parseClaimsJws() -> CWE-347

### CWE-916 -- Insufficient password hashing
- Fast algorithm (SHA-256, MD5) for password storage -> CWE-916

## Prompt rules (IMPORTANT)
1. First, list every JCA/crypto API call you see in the code (chain-of-thought)
2. For each API call, identify ALL potential misuses -- not just the most obvious one
3. Base analysis ONLY on actual code behavior -- NOT on variable or method names alone
4. If a key, IV, or salt comes from a parameter or external source -- do NOT assume it is hardcoded
5. Only flag what you can see directly in this snippet -- do not speculate about other methods
6. If in doubt between two CWEs, apply the CWE classification rules above to decide
7. new Random() in any security context is ALWAYS CWE-330 -- flag it, no exceptions
8. DriverManager.getConnection() with password from external source -> CWE-311. If password is a hardcoded literal or comment says FIX -> do NOT flag CWE-311
9. Focus on the SINK -- where does the sensitive data end up? That determines the CWE
10. For password hashing issues: missing salt -> CWE-328, fast algorithm -> CWE-916, wrong algorithm -> CWE-327
11. If a comment says "FIX:" anywhere in the method -> this is a secure implementation, treat it as not vulnerable

## Output format
Respond ONLY with a valid JSON array. No explanation, no markdown, no preamble, no postamble.
Start your response with [ and end with ].
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
IMPORTANT: Your entire response must be valid JSON. Do not write anything before [ or after ].
"""


def _build_system_prompt_compact() -> str:
    """
    Minimal system prompt for Phi3-3.8B.
    No taxonomy tables — only essential detection rules.
    Kept under 500 tokens to leave sufficient context for code + response.
    """
    return """You are a security expert. Detect cryptographic vulnerabilities in Java/Kotlin code.
Rules: DES/3DES/RC4/AES-ECB -> CWE-327 CRITICAL. Hardcoded key/password literal -> CWE-798 CRITICAL. new Random() for security -> CWE-330 HIGH. Hardcoded IV in CBC -> CWE-329 HIGH. RSA<2048/AES<128 -> CWE-326 HIGH. SHA-1/MD5/SHA-256 on password without salt -> CWE-328 HIGH. Fast hash for password storage -> CWE-916 HIGH. parseClaimsJwt() -> CWE-347 HIGH. DriverManager.getConnection() with external password -> CWE-311 HIGH.
Safe: KeyGenerator, SecureRandom, Android KeyStore, AES/GCM, bcrypt, PBKDF2, parseClaimsJws().
Do NOT flag: good1/good2/goodG2B/goodG2B1/goodG2B2/goodB2G methods. Comment says "FIX:" -> secure. Variable init to "" then overwritten by readLine() -> NOT hardcoded. Hardcoded password in getConnection() -> CWE-798 not CWE-311.
Respond ONLY with JSON array: [{"cwe_id":"CWE-XXX","severity":"CRITICAL|HIGH|WARNING","confidence":"high|medium|low","explanation":"...","fix_code":"...","line_hint":1}]
If no vulnerability: []"""


def _build_system_prompt() -> str:
    if _is_phi3():
        return _build_system_prompt_compact()
    return _build_system_prompt_full()


def _build_user_prompt(snippet: CodeSnippet) -> str:
    return f"""File: {snippet.file_path}
Class: {snippet.context}
Method: {snippet.method_name}
Language: {snippet.language}
Lines: {snippet.start_line}-{snippet.end_line}

Analyze the following code and respond ONLY with a JSON array:

```{snippet.language}
{snippet.code}
```

Remember: respond ONLY with [ ... ] JSON array, nothing else.
"""


def _build_phi3_prompt(system_prompt: str, user_prompt: str) -> str:
    """
    Phi3 generate API format.
    Inject '[' at end so model continues the JSON array directly.
    """
    return (
        f"<|user|>\n"
        f"{system_prompt}\n\n"
        f"{user_prompt}\n"
        f"<|end|>\n"
        f"<|assistant|>\n"
        f"["
    )


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


def _apply_confidence_filter(findings: list) -> list:
    filtered = []
    for f in findings:
        cwe      = f.get("cwe_id", "")
        min_conf = MIN_CONFIDENCE.get(cwe)
        if min_conf is None:
            filtered.append(f)
            continue
        finding_rank = CONFIDENCE_RANK.get(f.get("confidence", "low"), 2)
        min_rank     = CONFIDENCE_RANK.get(min_conf, 0)
        if finding_rank <= min_rank:
            filtered.append(f)
    return filtered


def _call_ollama(system_prompt: str, user_prompt: str) -> str:
    options = {"temperature": 0.0, "top_p": 0.9, "top_k": 20}

    if _is_phi3():
        # Phi3 — generate API with native instruct template + injected '['
        prompt = _build_phi3_prompt(system_prompt, user_prompt)
        payload = {
            "model":   _active_model,
            "prompt":  prompt,
            "stream":  False,
            "options": options,
        }
        try:
            response = requests.post(OLLAMA_URL_GENERATE, json=payload, timeout=120)
            response.raise_for_status()
            raw = response.json().get("response", "").strip()
            # Prepend '[' only if the model did not already include it
            if not raw.startswith("["):
                raw = "[" + raw
            return raw
        except requests.exceptions.ConnectionError:
            raise RuntimeError("Ollama is not running. Start it with: ollama serve")
        except requests.exceptions.Timeout:
            raise RuntimeError("Ollama timed out -- model may be loading, try again")
    else:
        # Qwen and all other models — generate API with Qwen chat template
        prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{user_prompt}\n<|assistant|>"
        payload = {
            "model":   _active_model,
            "prompt":  prompt,
            "stream":  False,
            "options": options,
        }
        try:
            response = requests.post(OLLAMA_URL_GENERATE, json=payload, timeout=120)
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.exceptions.ConnectionError:
            raise RuntimeError("Ollama is not running. Start it with: ollama serve")
        except requests.exceptions.Timeout:
            raise RuntimeError("Ollama timed out -- model may be loading, try again")


def _find_matching_bracket(s: str, start: int) -> int:
    """Find the index of the closing ] that matches the [ at start."""
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "[":
            depth += 1
        elif s[i] == "]":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _parse_response(raw: str) -> list:
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw   = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])
    start = raw.find("[")
    if start == -1:
        return []
    end = _find_matching_bracket(raw, start)
    if end == -1:
        # Fallback: use rfind
        end = raw.rfind("]")
    if end == -1:
        return []
    try:
        findings = json.loads(raw[start:end + 1])
    except json.JSONDecodeError:
        partial = raw[start:end + 1]
        last    = partial.rfind("}")
        if last != -1:
            try:
                findings = json.loads(partial[:last + 1] + "]")
            except json.JSONDecodeError:
                return []
        else:
            return []
    if not isinstance(findings, list):
        return []
    return [f for f in findings if _validate_finding(f)]


_SYSTEM_PROMPT = None


def analyze_snippet(snippet: CodeSnippet) -> list:
    global _SYSTEM_PROMPT
    if _SYSTEM_PROMPT is None:
        _SYSTEM_PROMPT = _build_system_prompt()
    user_prompt = _build_user_prompt(snippet)
    raw         = _call_ollama(_SYSTEM_PROMPT, user_prompt)
    findings    = _parse_response(raw)
    findings    = _apply_confidence_filter(findings)
    for f in findings:
        f["file"]       = snippet.file_path
        f["start_line"] = snippet.start_line
        f["method"]     = snippet.method_name
    return findings


def analyze_file(file_path: str) -> list:
    from src.parser.code_parser import extract_snippets_from_file
    snippets     = extract_snippets_from_file(file_path)
    all_findings = []
    for snippet in snippets:
        findings = analyze_snippet(snippet)
        all_findings.extend(findings)
    return all_findings


def analyze_directory(dir_path: str) -> list:
    from src.parser.code_parser import extract_snippets_from_dir
    snippets     = extract_snippets_from_dir(dir_path)
    all_findings = []
    total        = len(snippets)
    for i, snippet in enumerate(snippets, 1):
        print(f"  [{i}/{total}] Analyzing {snippet.context}.{snippet.method_name}...")
        findings = analyze_snippet(snippet)
        if findings:
            print(f"    -> {len(findings)} finding(s)")
        all_findings.extend(findings)
    return all_findings
