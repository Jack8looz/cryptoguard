import json
import random
import sys
import os
import time
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.analyzer.llm_engine import analyze_snippet, set_model, get_model
from src.parser.code_parser import CodeSnippet

VALIDATION_PATH = Path(__file__).parent.parent.parent / "dataset" / "splits" / "validation.jsonl"
RESULTS_DIR     = Path(__file__).parent.parent.parent / "results"

VALID_CWES = [
    "CWE-311", "CWE-326", "CWE-327", "CWE-328",
    "CWE-329", "CWE-330", "CWE-347", "CWE-798", "CWE-916"
]


@dataclass
class EvalResult:
    record_id:      str
    cwe_id:         str
    is_vulnerable:  bool
    predicted_vuln: bool
    predicted_cwe:  Optional[str]
    confidence:     Optional[str]
    correct_cwe:    bool
    elapsed:        float
    error:          Optional[str] = None


def load_validation_set(sample_per_cwe: Optional[int] = None) -> List[dict]:
    records = []
    with open(VALIDATION_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    if sample_per_cwe is None:
        return records

    by_cwe = defaultdict(list)
    for r in records:
        by_cwe[r["cwe_id"]].append(r)

    sampled = []
    for cwe, items in sorted(by_cwe.items()):
        n        = min(sample_per_cwe, len(items))
        vuln     = [x for x in items if x["is_vulnerable"]]
        secure   = [x for x in items if not x["is_vulnerable"]]
        n_vuln   = max(1, round(n * len(vuln) / len(items)))
        n_secure = max(1, n - n_vuln)
        n_vuln   = min(n_vuln,   len(vuln))
        n_secure = min(n_secure, len(secure))
        random.seed(42)
        sampled.extend(random.sample(vuln,   n_vuln))
        sampled.extend(random.sample(secure, n_secure))
        print(f"  {cwe}: sampled {n_vuln} vulnerable + {n_secure} secure = {n_vuln+n_secure}")

    return sampled


def record_to_snippet(record: dict) -> CodeSnippet:
    return CodeSnippet(
        file_path   = record.get("file_origin", record["id"] + ".java"),
        language    = record.get("language", "java"),
        method_name = record.get("id", "unknown"),
        start_line  = 1,
        end_line    = len(record["code"].splitlines()),
        code        = record["code"],
        context     = record.get("cwe_id", "Unknown"),
    )


def evaluate_record(record: dict) -> EvalResult:
    snippet = record_to_snippet(record)
    t0      = time.time()
    error   = None

    try:
        findings = analyze_snippet(snippet)
    except RuntimeError as e:
        # Timeout or connection error — treat as no findings, log the error
        findings = []
        error    = str(e)

    elapsed        = time.time() - t0
    predicted_vuln = len(findings) > 0
    predicted_cwe  = findings[0].get("cwe_id") if findings else None
    confidence     = findings[0].get("confidence") if findings else None
    correct_cwe    = predicted_cwe == record["cwe_id"] if predicted_vuln else True

    return EvalResult(
        record_id      = record["id"],
        cwe_id         = record["cwe_id"],
        is_vulnerable  = record["is_vulnerable"],
        predicted_vuln = predicted_vuln,
        predicted_cwe  = predicted_cwe,
        confidence     = confidence,
        correct_cwe    = correct_cwe,
        elapsed        = elapsed,
        error          = error,
    )


def compute_metrics(results: List[EvalResult], cwe: str) -> dict:
    cwe_results = [r for r in results if r.cwe_id == cwe]
    if not cwe_results:
        return {}

    vuln_results   = [r for r in cwe_results if r.is_vulnerable]
    secure_results = [r for r in cwe_results if not r.is_vulnerable]

    tp = sum(1 for r in vuln_results   if r.predicted_vuln)
    fn = sum(1 for r in vuln_results   if not r.predicted_vuln)
    fp = sum(1 for r in secure_results if r.predicted_vuln)
    tn = sum(1 for r in secure_results if not r.predicted_vuln)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    correct_cwe_count = sum(1 for r in cwe_results if r.predicted_vuln and r.correct_cwe)
    cwe_accuracy      = correct_cwe_count / tp if tp > 0 else 0.0

    errors = sum(1 for r in cwe_results if r.error)

    return {
        "cwe":          cwe,
        "total":        len(cwe_results),
        "vulnerable":   len(vuln_results),
        "secure":       len(secure_results),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision":    round(precision, 3),
        "recall":       round(recall, 3),
        "f1":           round(f1, 3),
        "cwe_accuracy": round(cwe_accuracy, 3),
        "errors":       errors,
    }


def print_metrics_table(all_metrics: List[dict], model_name: str = ""):
    label = f" [{model_name}]" if model_name else ""
    print(f"\n{'='*75}")
    print(f"  Results{label}")
    print(f"{'CWE':<12} {'Total':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} "
          f"{'Prec':>6} {'Rec':>6} {'F1':>6} {'Err':>4}")
    print(f"{'-'*75}")
    total_tp = total_fp = total_fn = total_tn = total_err = 0
    for m in all_metrics:
        if not m:
            continue
        f1_str = f"{m['f1']:.3f}"
        flag   = " ✖" if m["f1"] < 0.5 else (" !" if m["f1"] < 0.7 else "")
        err    = m.get("errors", 0)
        print(f"{m['cwe']:<12} {m['total']:>6} {m['tp']:>4} {m['fp']:>4} "
              f"{m['fn']:>4} {m['tn']:>4} {m['precision']:>6.3f} "
              f"{m['recall']:>6.3f} {f1_str:>6}{flag}  {err:>3}")
        total_tp  += m["tp"]; total_fp += m["fp"]
        total_fn  += m["fn"]; total_tn += m["tn"]
        total_err += err

    total     = total_tp + total_fp + total_fn + total_tn
    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    overall_f1= 2 * overall_p * overall_r / (overall_p + overall_r) if (overall_p + overall_r) > 0 else 0
    print(f"{'-'*75}")
    print(f"{'OVERALL':<12} {total:>6} {total_tp:>4} {total_fp:>4} "
          f"{total_fn:>4} {total_tn:>4} {overall_p:>6.3f} "
          f"{overall_r:>6.3f} {overall_f1:>6.3f}   {total_err:>2}")
    print(f"{'='*75}")
    print(f"\nLegend: ✖ = F1 < 0.50  ! = F1 < 0.70  Err = timeout/connection errors")


def run_evaluation(sample_per_cwe: Optional[int] = None,
                   output_file: Optional[str] = None,
                   model: Optional[str] = None):

    if model:
        set_model(model)

    active = get_model()
    mode   = f"sampled ({sample_per_cwe} per CWE)" if sample_per_cwe else "full"
    print(f"\nCryptoGuard Evaluation — {mode} — model: {active}")
    print(f"Validation set: {VALIDATION_PATH}")

    print(f"\nLoading validation set...")
    records = load_validation_set(sample_per_cwe)
    print(f"Total records to evaluate: {len(records)}")

    est_min = len(records) * 17 / 60
    print(f"Estimated time: {est_min:.0f}-{est_min*1.3:.0f} minutes\n")

    results = []
    total   = len(records)
    t_start = time.time()

    for i, record in enumerate(records, 1):
        cwe      = record["cwe_id"]
        vuln_str = "vuln  " if record["is_vulnerable"] else "secure"
        print(f"  [{i:>3}/{total}] {cwe} | {vuln_str} | {record['id'][:40]}...", end=" ", flush=True)

        result = evaluate_record(record)
        results.append(result)

        if result.error:
            status = "ERR"
        elif result.is_vulnerable and result.predicted_vuln:
            status = "TP"
        elif result.is_vulnerable and not result.predicted_vuln:
            status = "FN ✖"
        elif not result.is_vulnerable and result.predicted_vuln:
            status = "FP ✖"
        else:
            status = "TN"

        cwe_note = f"→{result.predicted_cwe}" if result.predicted_vuln else ""
        err_note = f" [ERR: {result.error[:30]}]" if result.error else ""
        print(f"{status} {cwe_note} ({result.elapsed:.1f}s){err_note}")

        if i % 10 == 0:
            elapsed   = time.time() - t_start
            remaining = (elapsed / i) * (total - i)
            errors    = sum(1 for r in results if r.error)
            print(f"\n  --- Progress: {i}/{total} | "
                  f"Elapsed: {elapsed/60:.1f}m | "
                  f"Remaining: {remaining/60:.1f}m | "
                  f"Errors: {errors} ---\n")

    all_metrics = [compute_metrics(results, cwe) for cwe in VALID_CWES]
    print_metrics_table([m for m in all_metrics if m], model_name=active)

    RESULTS_DIR.mkdir(exist_ok=True)
    model_tag = active.replace(":", "_").replace(".", "_")
    tag       = f"sample{sample_per_cwe}" if sample_per_cwe else "full"
    out       = output_file or str(RESULTS_DIR / f"eval_{model_tag}_{tag}.json")

    output_data = {
        "mode":    mode,
        "model":   active,
        "total":   len(records),
        "metrics": [m for m in all_metrics if m],
        "results": [
            {
                "id":            r.record_id,
                "cwe_id":        r.cwe_id,
                "is_vulnerable": r.is_vulnerable,
                "predicted":     r.predicted_vuln,
                "predicted_cwe": r.predicted_cwe,
                "confidence":    r.confidence,
                "elapsed":       round(r.elapsed, 2),
                "error":         r.error,
            }
            for r in results
        ]
    }
    with open(out, "w") as f:
        json.dump(output_data, f, indent=2)

    total_errors = sum(1 for r in results if r.error)
    print(f"\nResults saved to: {out}")
    print(f"Total errors (timeouts): {total_errors}")
    total_time = time.time() - t_start
    print(f"Total time: {total_time/60:.1f} minutes")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate CryptoGuard on validation set")
    parser.add_argument("--sample", "-s", type=int, default=None,
                        help="Number of examples per CWE (default: all)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Output JSON file path")
    parser.add_argument("--model",  "-m", type=str, default=None,
                        help="Ollama model name (default: qwen2.5-coder:7b)")
    args = parser.parse_args()
    run_evaluation(sample_per_cwe=args.sample,
                   output_file=args.output,
                   model=args.model)
