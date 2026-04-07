import json
import random
import os
from collections import defaultdict

random.seed(42)

RAW_DIR    = os.path.expanduser("~/cryptoguard/dataset/raw")
SPLIT_DIR  = os.path.expanduser("~/cryptoguard/dataset/splits")
LABEL_DIR  = os.path.expanduser("~/cryptoguard/dataset/labelled")
os.makedirs(SPLIT_DIR, exist_ok=True)
os.makedirs(LABEL_DIR, exist_ok=True)

# Load all sources
sources = [
    os.path.join(RAW_DIR, "juliet_extracted.jsonl"),
    os.path.join(RAW_DIR, "synthetic_examples.jsonl"),
]

all_records = []
for path in sources:
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                all_records.append(json.loads(line))

print(f"Total records loaded: {len(all_records)}")

# Deduplicate by id
seen = set()
unique = []
for r in all_records:
    if r["id"] not in seen:
        seen.add(r["id"])
        unique.append(r)
print(f"After dedup: {len(unique)}")

# Write master labelled file
master_path = os.path.join(LABEL_DIR, "master.jsonl")
with open(master_path, "w", encoding="utf-8") as f:
    for r in unique:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"Master dataset: {master_path}")

# Group by CWE for stratified split
by_cwe = defaultdict(list)
for r in unique:
    by_cwe[r["cwe_id"]].append(r)

train, val, test = [], [], []

for cwe, items in sorted(by_cwe.items()):
    random.shuffle(items)
    n = len(items)
    n_test = max(1, int(n * 0.15))
    n_val  = max(1, int(n * 0.15))
    n_train = n - n_test - n_val

    test.extend(items[:n_test])
    val.extend(items[n_test:n_test + n_val])
    train.extend(items[n_test + n_val:])

    print(f"  {cwe}: {n_train} train / {n_val} val / {n_test} test")

# Shuffle each split
random.shuffle(train)
random.shuffle(val)
random.shuffle(test)

def write_split(records, name):
    path = os.path.join(SPLIT_DIR, f"{name}.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return path

write_split(train, "train")
write_split(val,   "validation")
write_split(test,  "test")

print(f"\nSplit complete:")
print(f"  Train:      {len(train):>5} examples")
print(f"  Validation: {len(val):>5} examples")
print(f"  Test:       {len(test):>5} examples")
print(f"  Total:      {len(unique):>5} examples")
print(f"\nWARNING: Do not open test.jsonl until Phase 5 benchmarking.")