"""
SpotBugs + FindSecBugs benchmark harness for CryptoGuard.

Wraps each test snippet in a compilable Java class, compiles it, runs SpotBugs
with the FindSecBugs plugin, maps detected bug patterns to CWEs, and computes
precision/recall/F1 against the locked test set.

Tools:
  - SpotBugs 4.8.3 (bundled in tools/spotbugs-4.8.3/)
  - FindSecBugs 1.14.0 (extracted to tools/findsecbugs-cli/)

Usage:
    python -m src.benchmarks.spotbugs_runner
"""

import json
import os
import re
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT         = Path(__file__).parent.parent.parent
TEST_PATH    = ROOT / "dataset" / "splits" / "test.jsonl"
RESULTS_DIR  = ROOT / "results"

FSB_CLI_DIR  = ROOT / "tools" / "findsecbugs-cli"
FSB_PLUGIN   = FSB_CLI_DIR / "lib" / "findsecbugs-plugin-1.14.0.jar"
FSB_INCLUDE  = FSB_CLI_DIR / "include.xml"

# ---------------------------------------------------------------------------
# Build classpath once (all JARs in findsecbugs-cli/lib/)
# ---------------------------------------------------------------------------

def _build_classpath() -> str:
    jars = sorted(FSB_CLI_DIR.glob("lib/*.jar"))
    if not jars:
        raise RuntimeError(f"No JARs found in {FSB_CLI_DIR}/lib/. Run setup first.")
    return ":".join(str(j) for j in jars)

_CLASSPATH = None  # lazy-init


def _get_classpath() -> str:
    global _CLASSPATH
    if _CLASSPATH is None:
        _CLASSPATH = _build_classpath()
    return _CLASSPATH


# ---------------------------------------------------------------------------
# Bug-pattern abbreviation → CWE mapping
# Only include patterns directly relevant to our 9-CWE taxonomy.
# ---------------------------------------------------------------------------

ABBREV_TO_CWE: dict[str, str] = {
    # CWE-311: Missing Encryption (unencrypted network transport)
    "SECUS":   "CWE-311",   # UNENCRYPTED_SOCKET
    "SECUSS":  "CWE-311",   # UNENCRYPTED_SERVER_SOCKET

    # CWE-326: Inadequate Key Size
    "SECRKS":  "CWE-326",   # RSA_KEY_SIZE
    "SECBKS":  "CWE-326",   # BLOWFISH_KEY_SIZE
    "SECHAZ":  "CWE-326",   # HAZELCAST_SYMMETRIC_ENCRYPTION

    # CWE-327: Use of Broken / Risky Cryptographic Algorithm
    "SECDU":   "CWE-327",   # DES_USAGE
    "SECTDU":  "CWE-327",   # TDES_USAGE
    "SECECB":  "CWE-327",   # ECB_MODE
    "SECNC":   "CWE-327",   # NULL_CIPHER
    "CIPINT":  "CWE-327",   # CIPHER_INTEGRITY (no authenticated encryption)
    "SECRNP":  "CWE-327",   # RSA_NO_PADDING

    # CWE-328: Use of Weak Hash
    "SECMD5":  "CWE-328",   # WEAK_MESSAGE_DIGEST_MD5
    "SECSHA1": "CWE-328",   # WEAK_MESSAGE_DIGEST_SHA1
    "SECCMD":  "CWE-328",   # CUSTOM_MESSAGE_DIGEST

    # CWE-329: Predictable / Hardcoded IV
    "STAIV":   "CWE-329",   # STATIC_IV

    # CWE-330: Use of Insufficiently Random Values
    "SECPR":   "CWE-330",   # PREDICTABLE_RANDOM
    "SECPRS":  "CWE-330",   # PREDICTABLE_RANDOM_SCALA

    # CWE-798: Use of Hard-coded Credentials
    "SECHCK":  "CWE-798",   # HARD_CODE_KEY
    "SECHCP":  "CWE-798",   # HARD_CODE_PASSWORD
}

# CWEs for which FindSecBugs has no applicable detector in our test set:
#   CWE-347 (JWT): test snippets use Auth0/JJWT library → won't compile and
#                  FindSecBugs has no JWT-verification rule.
#   CWE-916 (insufficient password hashing): no dedicated detector;
#           WEAK_MESSAGE_DIGEST covers SHA-1/MD5 but not SHA-256 misuse.
SPOTBUGS_UNSUPPORTED: set[str] = {"CWE-347", "CWE-916"}

# ---------------------------------------------------------------------------
# Java wrapper — full Juliet-compatible harness
# ---------------------------------------------------------------------------

# All CWE cross-class stubs (Juliet 51b–75b pattern) — non-public so they
# can live in the same file as the public SnippetWrapper class.
_JULIET_CROSS_CLASS_STUBS = """\
class IO {
    public static final boolean STATIC_FINAL_FALSE = false;
    public static final boolean STATIC_FINAL_TRUE = true;
    public static final int STATIC_FINAL_FIVE = 5;
    public static boolean staticFalse = false;
    public static boolean staticTrue = true;
    public static int staticFive = 5;
    public static java.util.logging.Logger logger =
        java.util.logging.Logger.getLogger("IO");
    public static boolean staticReturnsFalse() { return false; }
    public static boolean staticReturnsTrue() { return true; }
    public static boolean staticReturnsTrueOrFalse() { return false; }
    public static void writeLine(Object o) {}
    public static void writeLine(String s) {}
    public static String toHex(byte[] b) { return ""; }
    public static String toHex(char[] b) { return ""; }
}

class Container<T> {
    public T containerOne;
}

class CWE259_Hard_Coded_Password__driverManager_22b {
    public String badSource() throws Throwable { return ""; }
    public String goodG2B1Source() throws Throwable { return ""; }
    public String goodG2B2Source() throws Throwable { return ""; }
}
class CWE259_Hard_Coded_Password__driverManager_52b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
}
class CWE259_Hard_Coded_Password__driverManager_73b {
    public void badSink(java.util.LinkedList<String> d) throws Throwable {}
    public void goodG2BSink(java.util.LinkedList<String> d) throws Throwable {}
}
class CWE259_Hard_Coded_Password__driverManager_75b {
    public void badSink(Object d) throws Throwable {}
    public void goodG2BSink(Object d) throws Throwable {}
}
class CWE259_Hard_Coded_Password__kerberosKey_52b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
}
class CWE259_Hard_Coded_Password__kerberosKey_67b {
    public void badSink(Container<String> d) throws Throwable {}
    public void goodG2BSink(Container<String> d) throws Throwable {}
}
class CWE259_Hard_Coded_Password__kerberosKey_72b {
    public void badSink(java.util.Vector<String> d) throws Throwable {}
    public void goodG2BSink(java.util.Vector<String> d) throws Throwable {}
}
class CWE259_Hard_Coded_Password__kerberosKey_75b {
    public void badSink(Object d) throws Throwable {}
    public void goodG2BSink(Object d) throws Throwable {}
}
class CWE259_Hard_Coded_Password__passwordAuth_71b {
    public void badSink(Object d) throws Throwable {}
    public void goodG2BSink(Object d) throws Throwable {}
}
class CWE319_Cleartext_Tx_Sensitive_Info__URLConnection_driverManager_51b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
    public void goodB2GSink(String d) throws Throwable {}
}
class CWE319_Cleartext_Tx_Sensitive_Info__URLConnection_driverManager_53b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
    public void goodB2GSink(String d) throws Throwable {}
}
class CWE319_Cleartext_Tx_Sensitive_Info__URLConnection_driverManager_54b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
    public void goodB2GSink(String d) throws Throwable {}
}
class CWE319_Cleartext_Tx_Sensitive_Info__URLConnection_driverManager_66b {
    public void badSink(String[] d) throws Throwable {}
    public void goodG2BSink(String[] d) throws Throwable {}
    public void goodB2GSink(String[] d) throws Throwable {}
}
class CWE319_Cleartext_Tx_Sensitive_Info__URLConnection_driverManager_68a {
    public static String data     = "";
    public static String password = "";
}
class CWE321_Hard_Coded_Cryptographic_Key__basic_51b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
}
class CWE321_Hard_Coded_Cryptographic_Key__basic_52b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
}
class CWE321_Hard_Coded_Cryptographic_Key__basic_54b {
    public void badSink(String d) throws Throwable {}
    public void goodG2BSink(String d) throws Throwable {}
}
class CWE321_Hard_Coded_Cryptographic_Key__basic_66b {
    public void badSink(String[] d) throws Throwable {}
    public void goodG2BSink(String[] d) throws Throwable {}
}
class CWE321_Hard_Coded_Cryptographic_Key__basic_68a {
    public static String data = "";
}
class CWE321_Hard_Coded_Cryptographic_Key__basic_68b {
    public void badSink() throws Throwable {}
    public void goodG2BSink() throws Throwable {}
}
"""

# Common intra-class method stubs added to SnippetWrapper body.
# These handle Juliet patterns where one method calls another within the class.
_JULIET_INSTANCE_STUBS = """\
    // --- Juliet common fields ---
    public static boolean PRIVATE_STATIC_FINAL_FALSE = false;
    public static boolean PRIVATE_STATIC_FINAL_TRUE  = true;
    public static int     PRIVATE_STATIC_FINAL_FIVE  = 5;
    public static boolean badPublicStatic      = false;
    public static boolean goodG2B1PublicStatic = false;
    public static boolean goodG2B2PublicStatic = false;
    private static int    privateFive   = 5;
    private static boolean privateTrue  = true;
    private static boolean privateFalse = false;
    private boolean goodG2B1_private    = false;
    public  String data            = "";
    public  String dataBad         = "";
    public  String dataGoodG2B     = "";
    public  String passwordGoodB2G = "";
    private static final java.util.logging.Logger logger =
        java.util.logging.Logger.getLogger("SnippetWrapper");
    private java.security.interfaces.RSAPublicKey  rsaPublicKey  = null;
    private java.security.interfaces.RSAPrivateKey rsaPrivateKey = null;

    // Juliet sibling-method stubs (added conditionally — see wrap_snippet).
    // STUB_PLACEHOLDER
"""

_JAVA_IMPORTS = """\
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.security.auth.kerberos.*;
import java.util.Random;
import java.sql.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;
import java.util.Base64;
"""


def wrap_snippet(code: str) -> str:
    """
    Wrap a method-level snippet in a full Juliet-compatible Java compilation
    unit. Includes the IO stub class and all cross-class Juliet stubs so that
    virtually all Juliet test cases compile out of the box.

    Sibling method stubs are added only when the snippet doesn't already define
    that method — this avoids "method already defined" compilation errors when
    the snippet IS the method being stubbed.
    """
    # All Juliet sibling methods that may need stubs
    sibling_stubs = [
        ("bad",                   "private void bad() throws Throwable {}"),
        ("badSink",               "private void badSink() throws Throwable {}"),
        ("badSink",               "private void badSink(String d) throws Throwable {}"),
        ("badSink",               "private void badSink(String[] d) throws Throwable {}"),
        ("badSource",             "private String badSource() throws Throwable { return \"\"; }"),
        ("goodG2B",               "private void goodG2B() throws Throwable {}"),
        ("goodG2B1",              "private void goodG2B1() throws Throwable {}"),
        ("goodG2B2",              "private void goodG2B2() throws Throwable {}"),
        ("goodB2G",               "private void goodB2G() throws Throwable {}"),
        ("goodB2G1",              "private void goodB2G1() throws Throwable {}"),
        ("goodB2G2",              "private void goodB2G2() throws Throwable {}"),
        ("goodG2BSink",           "private void goodG2BSink() throws Throwable {}"),
        ("goodG2BSink",           "private void goodG2BSink(String d) throws Throwable {}"),
        ("goodG2BSink",           "private void goodG2BSink(String[] d) throws Throwable {}"),
        ("goodB2GSink",           "private void goodB2GSink() throws Throwable {}"),
        ("goodB2GSink",           "private void goodB2GSink(String d) throws Throwable {}"),
        ("goodB2GSink",           "private void goodB2GSink(String[] d) throws Throwable {}"),
        ("goodG2BSource",         "private String goodG2BSource() throws Throwable { return \"\"; }"),
        ("goodG2B1Source",        "private String goodG2B1Source() throws Throwable { return \"\"; }"),
        ("goodG2B2Source",        "private String goodG2B2Source() throws Throwable { return \"\"; }"),
        ("goodG2B1_source",       "private String goodG2B1_source() throws Throwable { return \"\"; }"),
        ("privateReturnsTrue",    "private boolean privateReturnsTrue() { return true; }"),
        ("privateReturnsFalse",   "private boolean privateReturnsFalse() { return false; }"),
        ("staticReturnsTrue",     "private static boolean staticReturnsTrue() { return true; }"),
        ("staticReturnsFalse",    "private static boolean staticReturnsFalse() { return false; }"),
        ("staticReturnsTrueOrFalse", "private static boolean staticReturnsTrueOrFalse() { return false; }"),
    ]

    # Detect which method names are already defined in the snippet so we can
    # skip those stubs (avoid "already defined" compilation errors).
    # Use word-boundary anchors on access modifiers to avoid false matches on
    # variable names like goodG2B1_private (whose suffix looks like "private").
    defined_methods: set[str] = set(
        m.group(1)
        for m in re.finditer(
            r"\b(?:private|public|protected|void|static)\b[^(]+\b(\w+)\s*\(",
            code,
        )
    )

    stub_lines: list[str] = []
    seen_sigs: set[str] = set()   # deduplicate overloads we already added
    for method_name, stub_decl in sibling_stubs:
        if method_name in defined_methods:
            continue   # snippet defines this method — no stub needed
        if stub_decl in seen_sigs:
            continue
        seen_sigs.add(stub_decl)
        stub_lines.append(f"    {stub_decl}")

    stubs_block = "\n".join(stub_lines)
    instance_stubs = _JULIET_INSTANCE_STUBS.replace(
        "    // Juliet sibling-method stubs (added conditionally — see wrap_snippet).\n"
        "    // STUB_PLACEHOLDER",
        stubs_block,
    )

    return (
        _JAVA_IMPORTS + "\n"
        + _JULIET_CROSS_CLASS_STUBS + "\n"
        + "public class SnippetWrapper {\n"
        + instance_stubs + "\n"
        + code + "\n"
        + "}\n"
    )


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------

def compile_snippet(java_src: str, out_dir: str) -> bool:
    """Compile java_src path into out_dir. Returns True on success."""
    result = subprocess.run(
        ["javac", "-nowarn", "-d", out_dir, java_src],
        capture_output=True,
        timeout=30,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# SpotBugs execution
# ---------------------------------------------------------------------------

# Text output line pattern:
#   Priority Category Abbrev: Description  At File.java:[line N]
#   e.g.: H S SECHCK: Hard coded cryptographic key found  At SnippetWrapper.java:[line 12]
_LINE_RE = re.compile(r"^[HML]\s+S\s+(\w+):", re.MULTILINE)


def run_spotbugs(class_file: str) -> list[str]:
    """
    Run SpotBugs + FindSecBugs on a single .class file.
    Returns list of CWE IDs triggered (deduplicated).
    """
    cp = _get_classpath()
    cmd = [
        "java", "-cp", cp,
        "edu.umd.cs.findbugs.LaunchAppropriateUI",
        "-quiet",
        "-pluginList", str(FSB_PLUGIN),
        "-include", str(FSB_INCLUDE),
        "analyze",
        class_file,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return []

    triggered: set[str] = set()
    for match in _LINE_RE.finditer(result.stdout):
        abbrev = match.group(1)
        cwe = ABBREV_TO_CWE.get(abbrev)
        if cwe:
            triggered.add(cwe)
    return list(triggered)


# ---------------------------------------------------------------------------
# Per-snippet analysis
# ---------------------------------------------------------------------------

def analyze_snippet(record: dict) -> tuple[bool, str]:
    """
    Compile and scan one test record.
    Returns (predicted_vulnerable: bool, detail: str).
    """
    cwe  = record["cwe_id"]
    code = record["code"]

    # Unsupported CWEs — skip compilation entirely
    if cwe in SPOTBUGS_UNSUPPORTED:
        return False, "unsupported"

    wrapped = wrap_snippet(code)

    with tempfile.TemporaryDirectory() as tmpdir:
        java_path = os.path.join(tmpdir, "SnippetWrapper.java")
        with open(java_path, "w", encoding="utf-8") as f:
            f.write(wrapped)

        # Compile
        if not compile_snippet(java_path, tmpdir):
            return False, "compile_error"

        class_path = os.path.join(tmpdir, "SnippetWrapper.class")
        if not os.path.exists(class_path):
            return False, "compile_error"

        # Scan
        triggered_cwes = run_spotbugs(class_path)

    predicted = cwe in triggered_cwes
    detail = ",".join(sorted(triggered_cwes)) if triggered_cwes else "none"
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

    print(f"\nSpotBugs + FindSecBugs Benchmark — {len(records)} test examples")
    print(f"Supported CWEs : {sorted(set(ABBREV_TO_CWE.values()))}")
    print(f"Unsupported    : {sorted(SPOTBUGS_UNSUPPORTED)}\n")

    results = []
    total   = len(records)
    t_start = time.time()

    for i, record in enumerate(records, 1):
        cwe      = record["cwe_id"]
        is_vuln  = record["is_vulnerable"]

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

        vuln_label = "vuln  " if is_vuln else "secure"
        print(
            f"  [{i:>3}/{total}] {cwe} | {vuln_label} | {status:<2} | "
            f"{detail:<25} {record['id'][:30]}"
        )

        if i % 20 == 0:
            elapsed   = time.time() - t_start
            remaining = (elapsed / i) * (total - i)
            print(
                f"\n  --- {i}/{total} | "
                f"Elapsed: {elapsed/60:.1f}m | "
                f"Remaining: {remaining/60:.1f}m ---\n"
            )

    # -----------------------------------------------------------------------
    # Metrics
    # -----------------------------------------------------------------------

    by_cwe: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
    for r in results:
        by_cwe[r["cwe_id"]][r["status"].lower()] += 1

    print(f"\n{'='*70}")
    print(f"  SpotBugs + FindSecBugs 1.14.0 Results")
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
        note = " [no rule]" if cwe in SPOTBUGS_UNSUPPORTED else ""
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
    out_path = RESULTS_DIR / "eval_spotbugs_test.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "tool":    "spotbugs+findsecbugs",
                "version": "spotbugs-4.8.3+findsecbugs-1.14.0",
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
