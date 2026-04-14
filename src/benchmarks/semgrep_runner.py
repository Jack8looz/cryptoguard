import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

TEST_PATH    = Path(__file__).parent.parent.parent / "dataset" / "splits" / "test.jsonl"
RESULTS_DIR  = Path(__file__).parent.parent.parent / "results"

# Map Semgrep rule IDs to our CWE taxonomy
RULE_TO_CWE = {
    "java.lang.security.audit.crypto.use-of-default-aes.use-of-default-aes":               "CWE-327",
    "java.lang.security.audit.crypto.desede-is-deprecated.desede-is-deprecated":            "CWE-327",
    "java.lang.security.audit.crypto.des-is-deprecated.des-is-deprecated":                  "CWE-327",
    "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle":                       "CWE-329",
    "java.lang.security.audit.crypto.no-static-initialization-vector.no-static-initialization-vector": "CWE-329",
    "java.lang.security.audit.crypto.use-of-md5.use-of-md5":                               "CWE-328",
    "java.lang.security.audit.crypto.use-of-sha1.use-of-sha1":                             "CWE-328",
    "java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket":               "CWE-311",
}

# CWEs Semgrep cannot detect — always FN for vulnerable, TN for secure
SEMGREP_UNSUPPORTED = {"CWE-326", "CWE-330", "CWE-347", "CWE-798", "CWE-916"}


def wrap_snippet(code: str, language: str) -> str:
    """Wrap a method snippet in a compilable Java class."""
    imports = """import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Random;
import java.sql.*;
import java.io.*;
import java.util.logging.*;
"""
    return f"""
{imports}
public class SnippetWrapper {{
    private static final Logger logger = Logger.getLogger("test");
{code}
}}
"""


def run_semgrep_on_snippet(code: str, language: str = "java") -> list:
    """Run Semgrep on a single snippet. Returns list of triggered CWEs."""
    wrapped = wrap_snippet(code, language)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".java", delete=False, encoding="utf-8"
    ) as f:
        f.write(wrapped)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["semgrep", "--config", "p/java", tmp_path, "--json", "--quiet"],
            capture_output=True, text=True, timeout=30
        )
        if not result.stdout.strip():
            return []
        data     = json.loads(result.stdout)
        findings = data.get("results", [])
        cwes     = set()
        for f in findings:
            rule_id = f.get("check_id", "")
            cwe     = RULE_TO_CWE.get(rule_id)
            if cwe:
                cwes.add(cwe)
        return list(cwes)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return []
    finally:
        os.unlink(tmp_path)


def run_benchmark():
    records = []
    with open(TEST_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    print(f"\nSemgrep Benchmark — {len(records)} test examples")
    print(f"Supported CWEs: {sorted(RULE_TO_CWE.values())}")
    print(f"Unsupported:    {sorted(SEMGREP_UNSUPPORTED)}\n")

    results  = []
    total    = len(records)
    t_start  = time.time()

    for i, record in enumerate(records, 1):
        cwe        = record["cwe_id"]
        is_vuln    = record["is_vulnerable"]
        code       = record["code"]
        language   = record.get("language", "java")

        if cwe in SEMGREP_UNSUPPORTED:
            # Semgrep has no rule — TN for secure, FN for vulnerable
            predicted = False
            status    = "TN" if not is_vuln else "FN"
        else:
            triggered_cwes = run_semgrep_on_snippet(code, language)
            predicted      = cwe in triggered_cwes
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
        })

        print(f"  [{i:>3}/{total}] {cwe} | {'vuln  ' if is_vuln else 'secure'} | {status}  {record['id'][:35]}")

        if i % 20 == 0:
            elapsed   = time.time() - t_start
            remaining = (elapsed / i) * (total - i)
            print(f"\n  --- {i}/{total} | Elapsed: {elapsed/60:.1f}m | Remaining: {remaining/60:.1f}m ---\n")

    # Compute metrics per CWE
    from collections import defaultdict
    by_cwe = defaultdict(lambda: {"tp":0,"fp":0,"fn":0,"tn":0})
    for r in results:
        s = r["status"]
        by_cwe[r["cwe_id"]][s.lower()] += 1

    print(f"\n{'='*65}")
    print(f"  Semgrep Results")
    print(f"{'CWE':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    print(f"{'-'*65}")

    metrics = []
    for cwe in sorted(by_cwe.keys()):
        m   = by_cwe[cwe]
        tp, fp, fn, tn = m["tp"], m["fp"], m["fn"], m["tn"]
        prec = tp/(tp+fp) if (tp+fp) > 0 else 0.0
        rec  = tp/(tp+fn) if (tp+fn) > 0 else 0.0
        f1   = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0.0
        flag = " ✖" if f1 < 0.5 else (" !" if f1 < 0.7 else "")
        note = " [no rule]" if cwe in SEMGREP_UNSUPPORTED else ""
        print(f"{cwe:<12} {tp:>4} {fp:>4} {fn:>4} {tn:>4} {prec:>7.3f} {rec:>7.3f} {f1:>7.3f}{flag}{note}")
        metrics.append({"cwe":cwe,"tp":tp,"fp":fp,"fn":fn,"tn":tn,
                        "precision":round(prec,3),"recall":round(rec,3),"f1":round(f1,3)})

    # Overall
    ttp = sum(m["tp"] for m in by_cwe.values())
    tfp = sum(m["fp"] for m in by_cwe.values())
    tfn = sum(m["fn"] for m in by_cwe.values())
    ttn = sum(m["tn"] for m in by_cwe.values())
    op  = ttp/(ttp+tfp) if (ttp+tfp) > 0 else 0.0
    or_ = ttp/(ttp+tfn) if (ttp+tfn) > 0 else 0.0
    of1 = 2*op*or_/(op+or_) if (op+or_) > 0 else 0.0
    print(f"{'-'*65}")
    print(f"{'OVERALL':<12} {ttp:>4} {tfp:>4} {tfn:>4} {ttn:>4} {op:>7.3f} {or_:>7.3f} {of1:>7.3f}")
    print(f"{'='*65}")

    elapsed = time.time() - t_start
    print(f"\nTotal time: {elapsed/60:.1f} minutes")

    # Save
    RESULTS_DIR.mkdir(exist_ok=True)
    out = RESULTS_DIR / "eval_semgrep_test.json"
    with open(out, "w") as f:
        json.dump({"tool":"semgrep","total":len(records),"metrics":metrics,"results":results}, f, indent=2)
    print(f"Results saved to: {out}")


if __name__ == "__main__":
    run_benchmark()