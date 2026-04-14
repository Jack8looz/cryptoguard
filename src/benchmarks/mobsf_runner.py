"""
MobSF 4.4.5 benchmark harness for CryptoGuard.

For each test snippet:
  1. Wrap it in a minimal Android Java source file
  2. Package as ZIP (AndroidManifest.xml + .java source)
  3. POST /api/v1/upload  → receive file hash
  4. POST /api/v1/scan    → triggers analysis, returns full JSON report
  5. Extract code_analysis.findings; map rule IDs to our 9-CWE taxonomy
  6. Compute precision / recall / F1 per CWE

MobSF performs regex-based source scanning — no compilation required.

Usage:
    python -m src.benchmarks.mobsf_runner
"""

import io
import json
import time
import zipfile
from collections import defaultdict
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MOBSF_URL  = "http://localhost:8000"
API_KEY    = "043437255234693b3cd8efc2f7406e67884a47eb8cdc4b70ac20da14dd5194bd"
HEADERS    = {"Authorization": API_KEY}

ROOT        = Path(__file__).parent.parent.parent
TEST_PATH   = ROOT / "dataset" / "splits" / "test.jsonl"
RESULTS_DIR = ROOT / "results"

# Seconds to wait between scans — MobSF is single-threaded on analysis
SCAN_DELAY = 0.5

# ---------------------------------------------------------------------------
# MobSF rule ID → CWE mapping (derived from android_rules.yaml + probe scans)
# ---------------------------------------------------------------------------

RULE_TO_CWE: dict[str, str] = {
    # CWE-327: Use of Broken / Risky Cryptographic Algorithm
    "android_weak_ciphers":    "CWE-327",  # DES, DESede/3DES, RC4, RC2, Blowfish
    "android_aes_ecb":         "CWE-327",  # AES/ECB mode
    "android_rsa_no_oaep":     "CWE-327",  # RSA/NoPadding

    # CWE-328: Use of Weak Hash
    # (MobSF internally labels these CWE-327, but in our taxonomy MD5/SHA-1
    #  for hashing are CWE-328 — distinct from cipher algorithm weaknesses)
    "android_md5":             "CWE-328",  # MD5 hash usage
    "android_sha1":            "CWE-328",  # SHA-1 hash usage
    "android_weak_hash":       "CWE-328",  # MD4 and other weak digests

    # CWE-329: Not Using a Random IV with CBC Mode
    "android_weak_iv":         "CWE-329",  # Hardcoded hex IV byte arrays

    # CWE-330: Use of Insufficiently Random Values
    "android_insecure_random": "CWE-330",  # java.util.Random (not SecureRandom)

    # CWE-798: Use of Hard-coded Credentials
    # Rule fires on: password=, pass=, username=, secret=, key= assigned to
    # a string literal (1-100 chars).
    "android_hardcoded":       "CWE-798",
}

# CWEs for which MobSF has no applicable rule in our test set:
#   CWE-311: cleartext DB/socket — no DriverManager / Socket rule
#   CWE-326: key size — no key-length rule
#   CWE-347: JWT — no JWT rule
#   CWE-916: insufficient password hashing — no dedicated rule
MOBSF_UNSUPPORTED: set[str] = {"CWE-311", "CWE-326", "CWE-347", "CWE-916"}

# ---------------------------------------------------------------------------
# AndroidManifest.xml template (shared for all snippets)
# ---------------------------------------------------------------------------

_MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.cryptoguard.test"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33"/>
    <application android:label="CryptoGuardTest" android:allowBackup="false">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

# ---------------------------------------------------------------------------
# Java source wrapper
# ---------------------------------------------------------------------------

_JAVA_IMPORTS_BASE = """\
import android.app.Activity;
import android.os.Bundle;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.security.auth.kerberos.*;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;
import java.util.Base64;
"""

# Conditionally included only when the snippet actually uses Random, so that
# the MobSF regex `java\.util\.Random` does not fire on every snippet via the
# import line (which would create FP noise on all non-CWE-330 test cases).
_RANDOM_IMPORT = "import java.util.Random;\n"


import re as _re
_RANDOM_RE = _re.compile(
    r"(?<![a-zA-Z])(?:new\s+Random\s*\(|Math\.random\s*\(|java\.util\.Random)"
)

def _uses_random(code: str) -> bool:
    """
    Return True iff the snippet uses java.util.Random or Math.random.
    Avoids matching SecureRandom (which also contains "Random").
    """
    return bool(_RANDOM_RE.search(code))


def wrap_snippet(snippet_id: str, code: str) -> str:
    """
    Wrap a method-level snippet in a minimal Android Java compilation unit.
    The package + class name are stable per snippet_id, ensuring the ZIP hash
    is unique per snippet even for identical code bodies.
    MobSF's analysis is regex-based — the source does not need to compile.

    `import java.util.Random` is included only when the snippet uses Random,
    preventing the android_insecure_random rule from firing spuriously on
    every other snippet's import block.
    """
    # Embed snippet_id as a comment so duplicate-code snippets get distinct
    # MD5 hashes on upload (avoiding scan result aliasing).
    imports = _JAVA_IMPORTS_BASE
    if _uses_random(code):
        imports = _RANDOM_IMPORT + imports
    return (
        f"// CryptoGuard benchmark snippet: {snippet_id}\n"
        "package com.cryptoguard.test;\n\n"
        + imports + "\n"
        "public class SnippetWrapper {\n"
        "    private static final java.util.logging.Logger logger =\n"
        "        java.util.logging.Logger.getLogger(\"SnippetWrapper\");\n"
        "    private java.security.interfaces.RSAPublicKey rsaPublicKey = null;\n"
        "    private java.security.interfaces.RSAPrivateKey rsaPrivateKey = null;\n\n"
        + code + "\n"
        "}\n"
    )


def make_zip(snippet_id: str, code: str) -> bytes:
    """Build a ZIP in memory containing the manifest and wrapped Java source."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", _MANIFEST)
        zf.writestr(
            "src/com/cryptoguard/test/SnippetWrapper.java",
            wrap_snippet(snippet_id, code),
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# MobSF API helpers
# ---------------------------------------------------------------------------

def _upload(zip_bytes: bytes, filename: str) -> str:
    """Upload ZIP to MobSF. Returns the MD5 hash."""
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/upload",
        headers=HEADERS,
        files={"file": (filename, zip_bytes, "application/zip")},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("status") != "success":
        raise RuntimeError(f"Upload failed: {data}")
    return data["hash"]


def _scan(file_hash: str, filename: str) -> dict:
    """Trigger scan and return the full analysis JSON (synchronous)."""
    resp = requests.post(
        f"{MOBSF_URL}/api/v1/scan",
        headers=HEADERS,
        data={
            "scan_type": "zip",
            "file_name": filename,
            "hash": file_hash,
            "re_scan": "0",
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def extract_triggered_cwes(scan_result: dict, target_cwe: str) -> tuple[bool, list[str]]:
    """
    Parse code_analysis.findings from a MobSF scan result.
    Returns (predicted_vulnerable, list_of_triggered_cwes).
    """
    findings = scan_result.get("code_analysis", {}).get("findings", {})
    triggered: set[str] = set()
    for rule_id, detail in findings.items():
        cwe = RULE_TO_CWE.get(rule_id)
        if cwe:
            triggered.add(cwe)
    predicted = target_cwe in triggered
    return predicted, sorted(triggered)


def analyze_snippet(record: dict) -> tuple[bool, str]:
    """
    Upload, scan, and classify one test record.
    Returns (predicted_vulnerable: bool, detail: str).
    """
    cwe  = record["cwe_id"]
    code = record["code"]
    sid  = record["id"]

    if cwe in MOBSF_UNSUPPORTED:
        return False, "unsupported"

    zip_bytes = make_zip(sid, code)
    filename  = f"cg_{sid}.zip"

    try:
        file_hash   = _upload(zip_bytes, filename)
        scan_result = _scan(file_hash, filename)
    except Exception as exc:
        return False, f"api_error:{exc}"

    predicted, triggered = extract_triggered_cwes(scan_result, cwe)
    detail = ",".join(triggered) if triggered else "none"
    return predicted, detail


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark():
    records = []
    with open(TEST_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    print(f"\nMobSF 4.4.5 Benchmark — {len(records)} test examples")
    print(f"Supported CWEs : {sorted(set(RULE_TO_CWE.values()))}")
    print(f"Unsupported    : {sorted(MOBSF_UNSUPPORTED)}\n")

    results = []
    total   = len(records)
    t_start = time.time()

    for i, record in enumerate(records, 1):
        cwe     = record["cwe_id"]
        is_vuln = record["is_vulnerable"]

        predicted, detail = analyze_snippet(record)

        if is_vuln and predicted:
            status = "TP"
        elif is_vuln and not predicted:
            status = "FN"
        elif not is_vuln and predicted:
            status = "FP"
        else:
            status = "TN"

        results.append({
            "id":            record["id"],
            "cwe_id":        cwe,
            "is_vulnerable": is_vuln,
            "predicted":     predicted,
            "status":        status,
            "detail":        detail,
        })

        label = "vuln  " if is_vuln else "secure"
        print(
            f"  [{i:>3}/{total}] {cwe} | {label} | {status:<2} | "
            f"{detail:<35} {record['id'][:30]}"
        )

        if i % 20 == 0:
            elapsed   = time.time() - t_start
            remaining = (elapsed / i) * (total - i)
            print(
                f"\n  --- {i}/{total} | "
                f"Elapsed: {elapsed/60:.1f}m | "
                f"Remaining: {remaining/60:.1f}m ---\n"
            )

        time.sleep(SCAN_DELAY)

    # -----------------------------------------------------------------------
    # Per-CWE metrics
    # -----------------------------------------------------------------------

    by_cwe: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for r in results:
        by_cwe[r["cwe_id"]][r["status"].lower()] += 1

    print(f"\n{'='*70}")
    print(f"  MobSF 4.4.5 Results")
    print(f"{'CWE':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} "
          f"{'Prec':>7} {'Rec':>7} {'F1':>7}")
    print(f"{'-'*70}")

    metrics = []
    for cwe in sorted(by_cwe.keys()):
        m              = by_cwe[cwe]
        tp, fp, fn, tn = m["tp"], m["fp"], m["fn"], m["tn"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        flag = " ✖" if f1 < 0.5 else (" !" if f1 < 0.7 else "")
        note = " [no rule]" if cwe in MOBSF_UNSUPPORTED else ""
        print(
            f"{cwe:<12} {tp:>4} {fp:>4} {fn:>4} {tn:>4} "
            f"{prec:>7.3f} {rec:>7.3f} {f1:>7.3f}{flag}{note}"
        )
        metrics.append({
            "cwe":       cwe,
            "tp":        tp,
            "fp":        fp,
            "fn":        fn,
            "tn":        tn,
            "precision": round(prec, 3),
            "recall":    round(rec, 3),
            "f1":        round(f1, 3),
        })

    # Overall
    ttp = sum(m["tp"] for m in by_cwe.values())
    tfp = sum(m["fp"] for m in by_cwe.values())
    tfn = sum(m["fn"] for m in by_cwe.values())
    ttn = sum(m["tn"] for m in by_cwe.values())
    op  = ttp / (ttp + tfp) if (ttp + tfp) > 0 else 0.0
    or_ = ttp / (ttp + tfn) if (ttp + tfn) > 0 else 0.0
    of1 = 2 * op * or_ / (op + or_) if (op + or_) > 0 else 0.0
    print(f"{'-'*70}")
    print(
        f"{'OVERALL':<12} {ttp:>4} {tfp:>4} {tfn:>4} {ttn:>4} "
        f"{op:>7.3f} {or_:>7.3f} {of1:>7.3f}"
    )
    print(f"{'='*70}")

    elapsed = time.time() - t_start
    print(f"\nTotal time: {elapsed/60:.1f} minutes")

    # -----------------------------------------------------------------------
    # Save
    # -----------------------------------------------------------------------

    RESULTS_DIR.mkdir(exist_ok=True)
    out_path = RESULTS_DIR / "eval_mobsf_test.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "tool":    "mobsf",
                "version": "4.4.5",
                "total":   len(records),
                "metrics": metrics,
                "results": results,
            },
            f,
            indent=2,
        )
    print(f"Results saved to: {out_path}")


if __name__ == "__main__":
    run_benchmark()
