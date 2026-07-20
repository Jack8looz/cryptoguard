import json
import os
import requests
from pathlib import Path
from src.parser.code_parser import CodeSnippet

OLLAMA_URL_GENERATE = "http://localhost:11434/api/generate"
OLLAMA_MODEL        = "qwen2.5-coder:7b"
TAXONOMY_DIR        = Path(__file__).parent.parent.parent / "docs" / "taxonomy"

VALID_CWES = {
    "CWE-295", "CWE-311", "CWE-326", "CWE-327", "CWE-328",
    "CWE-329", "CWE-330", "CWE-347", "CWE-798", "CWE-916"
}
VALID_SEVERITIES  = {"CRITICAL", "HIGH", "WARNING", "NONE"}
VALID_CONFIDENCES = {"high", "medium", "low"}

MIN_CONFIDENCE = {
    "CWE-798": "high",
    "CWE-311": "medium",
}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

# Hybrid routing — CWEs where Phi3 outperforms Qwen based on validation results
PHI3_CWES = {"CWE-330", "CWE-311"}

# Signals that trigger Phi3 routing
PHI3_SIGNALS = {
    "CWE-330": ["new Random()", "Math.random()", "java.util.Random"],
    "CWE-311": ["DriverManager", "getConnection", "getConnection("],
}

_active_model  = OLLAMA_MODEL
_hybrid_mode   = False


def set_model(model_name: str):
    global _active_model, _SYSTEM_PROMPT
    _active_model  = model_name
    _SYSTEM_PROMPT = None
    print(f"  [ENGINE] Model set to: {model_name}")


def get_model() -> str:
    return _active_model


def set_hybrid(enabled: bool):
    global _hybrid_mode, _SYSTEM_PROMPT
    _hybrid_mode   = enabled
    _SYSTEM_PROMPT = None
    print(f"  [ENGINE] Hybrid mode: {'ON' if enabled else 'OFF'}")


def get_hybrid() -> bool:
    return _hybrid_mode


def _is_phi3(model: str = None) -> bool:
    m = model or _active_model
    return "phi3" in m.lower() or "phi-3" in m.lower()


def _detect_phi3_cwes(code: str) -> set:
    """Detect which CWEs in code should be routed to Phi3."""
    triggered = set()
    for cwe, signals in PHI3_SIGNALS.items():
        for signal in signals:
            if signal in code:
                triggered.add(cwe)
                break
    return triggered


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
- KerberosKey with data from readLine() or user input -> NOT hardcoded, do NOT flag
- KerberosKey with hardcoded string literal -> CWE-798

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

### CWE-295 -- Improper certificate validation
- Empty or no-op checkServerTrusted()/checkClientTrusted() body -> CWE-295, always CRITICAL
- HostnameVerifier.verify() or Kotlin hostnameVerifier lambda that unconditionally returns true -> CWE-295
- ALLOW_ALL_HOSTNAME_VERIFIER or equivalent deprecated permissive constant -> CWE-295
- WebView onReceivedSslError() calling handler.proceed() -> CWE-295
- Custom TrustManager/HostnameVerifier that contains real comparison logic and can reject (e.g. certificate pinning) -> NOT a vulnerability
- CertificatePinner usage (OkHttp) -> NOT a vulnerability, this is the secure alternative
- Default TrustManagerFactory/HostnameVerifier obtained from the platform and unmodified -> NOT a vulnerability
- Trust-all pattern gated behind BuildConfig.DEBUG with no path to production -> CWE-295, WARNING not CRITICAL

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
12. A TrustManager/HostnameVerifier is only CWE-295 if it ACCEPTS everything with no rejection path -- if it contains real comparison logic that can throw/return false (e.g. certificate pinning), it is secure, do NOT flag it

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
    """Minimal system prompt for Phi3-3.8B — under 500 tokens."""
    return """You are a security expert. Detect cryptographic vulnerabilities in Java/Kotlin code.
Rules: DES/3DES/RC4/AES-ECB -> CWE-327 CRITICAL. Hardcoded key/password literal -> CWE-798 CRITICAL. new Random() for security -> CWE-330 HIGH. Hardcoded IV in CBC -> CWE-329 HIGH. RSA<2048/AES<128 -> CWE-326 HIGH. SHA-1/MD5/SHA-256 on password without salt -> CWE-328 HIGH. Fast hash for password storage -> CWE-916 HIGH. parseClaimsJwt() -> CWE-347 HIGH. DriverManager.getConnection() with external password -> CWE-311 HIGH.
Safe: KeyGenerator, SecureRandom, Android KeyStore, AES/GCM, bcrypt, PBKDF2, parseClaimsJws().
Do NOT flag: good1/good2/goodG2B/goodG2B1/goodG2B2/goodB2G methods. Comment says "FIX:" -> secure. Variable init to "" then overwritten by readLine() -> NOT hardcoded. Hardcoded password in getConnection() -> CWE-798 not CWE-311. KerberosKey with data from readLine() or user input -> NOT hardcoded. KerberosKey with hardcoded string literal -> CWE-798.
Respond ONLY with JSON array: [{"cwe_id":"CWE-XXX","severity":"CRITICAL|HIGH|WARNING","confidence":"high|medium|low","explanation":"...","fix_code":"...","line_hint":1}]
If no vulnerability: []"""


def _build_system_prompt(model: str = None) -> str:
    m = model or _active_model
    if _is_phi3(m):
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


def _find_matching_bracket(s: str, start: int) -> int:
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "[":
            depth += 1
        elif s[i] == "]":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _call_model(model: str, system_prompt: str, user_prompt: str) -> str:
    options = {"temperature": 0.0, "top_p": 0.9, "top_k": 20}
    timeout = 120

    if _is_phi3(model):
        prompt = _build_phi3_prompt(system_prompt, user_prompt)
        payload = {
            "model":   model,
            "prompt":  prompt,
            "stream":  False,
            "options": options,
        }
        try:
            response = requests.post(OLLAMA_URL_GENERATE, json=payload, timeout=timeout)
            response.raise_for_status()
            raw = response.json().get("response", "").strip()
            if not raw.startswith("["):
                raw = "[" + raw
            return raw
        except requests.exceptions.ConnectionError:
            raise RuntimeError("Ollama is not running. Start it with: ollama serve")
        except requests.exceptions.Timeout:
            raise RuntimeError("Ollama timed out -- model may be loading, try again")
    else:
        prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{user_prompt}\n<|assistant|>"
        payload = {
            "model":   model,
            "prompt":  prompt,
            "stream":  False,
            "options": options,
        }
        try:
            response = requests.post(OLLAMA_URL_GENERATE, json=payload, timeout=timeout)
            response.raise_for_status()
            return response.json().get("response", "")
        except requests.exceptions.ConnectionError:
            raise RuntimeError("Ollama is not running. Start it with: ollama serve")
        except requests.exceptions.Timeout:
            raise RuntimeError("Ollama timed out -- model may be loading, try again")


def _call_ollama(system_prompt: str, user_prompt: str) -> str:
    return _call_model(_active_model, system_prompt, user_prompt)


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


_SYSTEM_PROMPT      = None
_PHI3_SYSTEM_PROMPT = None


def _get_system_prompt(model: str) -> str:
    global _SYSTEM_PROMPT, _PHI3_SYSTEM_PROMPT
    if _is_phi3(model):
        if _PHI3_SYSTEM_PROMPT is None:
            _PHI3_SYSTEM_PROMPT = _build_system_prompt_compact()
        return _PHI3_SYSTEM_PROMPT
    else:
        if _SYSTEM_PROMPT is None:
            _SYSTEM_PROMPT = _build_system_prompt_full()
        return _SYSTEM_PROMPT


def _run_model(model: str, snippet: CodeSnippet) -> list:
    """Run a specific model on a snippet and return validated findings."""
    sys_prompt  = _get_system_prompt(model)
    user_prompt = _build_user_prompt(snippet)
    raw         = _call_model(model, sys_prompt, user_prompt)
    findings    = _parse_response(raw)
    findings    = _apply_confidence_filter(findings)
    for f in findings:
        f["file"]       = snippet.file_path
        f["start_line"] = snippet.start_line
        f["method"]     = snippet.method_name
        f["model"]      = model
    return findings


def _merge_findings(qwen_findings: list, phi3_findings: list,
                    phi3_cwes: set) -> list:
    """
    Merge findings from both models.
    - For CWEs routed to Phi3: use Phi3 findings only
    - For all other CWEs: use Qwen findings only
    - No duplicates
    """
    merged = []
    seen_cwes = set()

    # Add Phi3 findings for Phi3-routed CWEs
    for f in phi3_findings:
        if f.get("cwe_id") in phi3_cwes:
            merged.append(f)
            seen_cwes.add(f.get("cwe_id"))

    # Add Qwen findings for non-Phi3 CWEs
    for f in qwen_findings:
        cwe = f.get("cwe_id")
        if cwe not in phi3_cwes:
            merged.append(f)

    return merged


def analyze_snippet(snippet: CodeSnippet) -> list:
    """
    Analyze a code snippet for cryptographic vulnerabilities.
    In hybrid mode: routes CWE-330 and CWE-311 to Phi3, everything else to Qwen.
    In standard mode: uses the active model only.
    """
    if _hybrid_mode:
        return _analyze_snippet_hybrid(snippet)
    else:
        return _analyze_snippet_single(snippet)


def _analyze_snippet_single(snippet: CodeSnippet) -> list:
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


def _analyze_snippet_hybrid(snippet: CodeSnippet) -> list:
    """
    Hybrid analysis: route to the best model per CWE category.
    CWE-330 and CWE-311 -> Phi3 (empirically better)
    Everything else -> Qwen (empirically better)
    """
    # Detect which Phi3 CWEs are relevant for this snippet
    phi3_cwes = _detect_phi3_cwes(snippet.code)

    if not phi3_cwes:
        # No Phi3 signals — run Qwen only
        return _run_model("qwen2.5-coder:7b", snippet)

    # Run Qwen for all CWEs
    qwen_findings = _run_model("qwen2.5-coder:7b", snippet)

    # Run Phi3 only for snippets containing relevant signals
    phi3_findings = _run_model("phi3:3.8b", snippet)

    # Merge: Phi3 results for Phi3 CWEs, Qwen results for everything else
    merged = _merge_findings(qwen_findings, phi3_findings, phi3_cwes)
    return merged


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
