import os
import json
import re
import hashlib

JULIET_DIR = os.path.expanduser("~/cryptoguard/dataset/raw/juliet")
OUTPUT_FILE = os.path.expanduser("~/cryptoguard/dataset/raw/juliet_extracted.jsonl")

CWE_MAP = {
    "CWE327_Use_Broken_Crypto":                ("CWE-327", "CRITICAL"),
    "CWE321_Hard_Coded_Cryptographic_Key":     ("CWE-798", "CRITICAL"),
    "CWE259_Hard_Coded_Password":              ("CWE-798", "CRITICAL"),
    "CWE328_Reversible_One_Way_Hash":          ("CWE-328", "HIGH"),
    "CWE759_Unsalted_One_Way_Hash":            ("CWE-328", "HIGH"),
    "CWE760_Predictable_Salt_One_Way_Hash":    ("CWE-328", "HIGH"),
    "CWE329_Not_Using_Random_IV_with_CBC_Mode":("CWE-329", "HIGH"),
    "CWE338_Weak_PRNG":                        ("CWE-330", "HIGH"),
    "CWE319_Cleartext_Tx_Sensitive_Info":      ("CWE-311", "CRITICAL"),
}

CAP_PER_FOLDER = {
    "CWE319_Cleartext_Tx_Sensitive_Info": 50,
}


def extract_method_body(source, start_match):
    """Extract a complete method body starting from a regex match using brace counting."""
    brace_pos = source.index('{', start_match.start())
    depth = 0
    i = brace_pos
    while i < len(source):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return source[start_match.start():i + 1].strip()
        i += 1
    return None


def extract_bad_method(source):
    """Extract the bad() method. Handles public/private/protected/static modifiers."""
    # Fix for Issue 1: support any combination of modifiers including static
    pattern = r'((?:(?:public|private|protected|static)\s+)*void\s+bad\s*\(\s*\)[^{]*\{)'
    match = re.search(pattern, source)
    if not match:
        return None
    return extract_method_body(source, match)


def extract_good_methods(source):
    """
    Extract ALL good methods: good(), good1(), good2(), goodG2B(), goodB2G(), etc.
    Fix for Issue 2: Juliet uses multiple good* variants, not just good().
    Returns a list of (method_name, code) tuples.
    """
    # Match any method starting with 'good' followed by optional suffix
    pattern = r'((?:(?:public|private|protected|static)\s+)*void\s+(good\w*)\s*\(\s*\)[^{]*\{)'
    results = []
    for match in re.finditer(pattern, source):
        method_name = match.group(2)
        # Skip the dispatcher good() that just calls good1(), good2(), etc.
        # Detect this by checking if the body only contains calls to other good methods
        body = extract_method_body(source, match)
        if body is None:
            continue
        # Skip thin dispatcher: body is short and only contains calls like good1(); good2();
        inner = body[body.index('{') + 1: body.rindex('}')].strip()
        is_dispatcher = (
            len(inner) < 60 and
            re.fullmatch(r'[\s\w();]+', inner) and
            re.search(r'good\d+\(\)', inner)
        )
        if is_dispatcher:
            continue
        results.append((method_name, body))
    return results


def extract_description(source):
    """Extract a human-readable description from Juliet file header comments."""
    match = re.search(r'BadSink\s*:\s*(.+)', source)
    if match:
        return match.group(1).strip()
    match = re.search(r'GoodSink\s*:\s*(.+)', source)
    if match:
        return match.group(1).strip()
    match = re.search(r'CWE:\s*\d+\s+(.+)', source)
    if match:
        return match.group(1).strip()
    return "Cryptographic vulnerability"


def make_id(filepath, kind):
    h = hashlib.md5(f"{filepath}{kind}".encode()).hexdigest()[:8]
    return f"juliet_{h}"


records = []
stats = {}

for folder_name, (cwe_id, severity) in CWE_MAP.items():
    folder_path = os.path.join(JULIET_DIR, folder_name)
    if not os.path.isdir(folder_path):
        print(f"SKIP (not found): {folder_name}")
        continue

    files = sorted([
        f for f in os.listdir(folder_path)
        if f.startswith("CWE") and f.endswith(".java")
    ])

    cap = CAP_PER_FOLDER.get(folder_name, 999)
    files = files[:cap]

    folder_records = []
    bad_count = 0
    good_count = 0
    skipped = 0

    for filename in files:
        filepath = os.path.join(folder_path, filename)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        description = extract_description(source)

        # Extract vulnerable snippet
        bad_code = extract_bad_method(source)
        if bad_code:
            folder_records.append({
                "id":            make_id(filepath, "bad"),
                "source":        "juliet",
                "language":      "java",
                "context":       "backend",
                "cwe_id":        cwe_id,
                "juliet_folder": folder_name,
                "is_vulnerable": True,
                "severity":      severity,
                "confidence":    "high",
                "description":   description,
                "code":          bad_code,
                "file_origin":   filename,
            })
            bad_count += 1
        else:
            skipped += 1

        # Extract ALL good method variants (good1, good2, goodG2B, goodB2G, etc.)
        good_methods = extract_good_methods(source)
        for method_name, good_code in good_methods:
            folder_records.append({
                "id":            make_id(filepath, method_name),
                "source":        "juliet",
                "language":      "java",
                "context":       "backend",
                "cwe_id":        cwe_id,
                "juliet_folder": folder_name,
                "is_vulnerable": False,
                "severity":      "NONE",
                "confidence":    "high",
                "description":   f"Secure version ({method_name}): {description}",
                "code":          good_code,
                "file_origin":   filename,
            })
            good_count += 1

    stats[folder_name] = {
        "files":   len(files),
        "bad":     bad_count,
        "good":    good_count,
        "skipped": skipped,
        "total":   bad_count + good_count,
    }
    print(f"{folder_name}: {bad_count} bad + {good_count} good = {bad_count + good_count} snippets ({skipped} files skipped)")
    records.extend(folder_records)

# Write JSONL output
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for record in records:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

print(f"\n{'='*60}")
print(f"Total snippets extracted: {len(records)}")
print(f"  Vulnerable (bad):  {sum(s['bad'] for s in stats.values())}")
print(f"  Secure (good):     {sum(s['good'] for s in stats.values())}")
print(f"Output: {OUTPUT_FILE}")
print(f"{'='*60}")

# Write a summary JSON alongside the JSONL
summary = {
    "total": len(records),
    "vulnerable": sum(s["bad"] for s in stats.values()),
    "secure": sum(s["good"] for s in stats.values()),
    "by_folder": stats,
    "cwe_coverage": list(set(r["cwe_id"] for r in records)),
}
summary_path = OUTPUT_FILE.replace(".jsonl", "_summary.json")
with open(summary_path, "w") as f:
    json.dump(summary, f, indent=2)
print(f"Summary: {summary_path}")
