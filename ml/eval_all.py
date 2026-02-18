from pathlib import Path
import json
from sklearn.metrics import classification_report, confusion_matrix, mean_absolute_error, r2_score
from joblib import load

def load_jsonl(fp: Path):
    rows = []
    for line in fp.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows

def eval_intent():
    model = load("ml/models/intent_tfidf/model.joblib")
    val = load_jsonl(Path("ml/data/intent_val.jsonl"))
    X = [r["text"] for r in val]
    y = [r["label"] for r in val]
    pred = model.predict(X)
    print("\n=== INTENT CLASSIFIER ===")
    print(classification_report(y, pred, zero_division=0))
    print("Confusion matrix:\n", confusion_matrix(y, pred))

def eval_sector():
    model = load("ml/models/sector_tfidf/model.joblib")
    val = load_jsonl(Path("ml/data/sector_val.jsonl"))
    X = [r["text"] for r in val]
    y = [r["labels"] for r in val]  # multilabel
    pred = model.predict(X)
    print("\n=== SECTOR CLASSIFIER (MULTILABEL) ===")
    print(classification_report(y, pred, zero_division=0))

def eval_vuln():
    model = load("ml/models/vuln_risk/model.joblib")
    val = load_jsonl(Path("ml/data/vuln_val.jsonl"))
    X = [r["features"] for r in val]
    y = [r["risk"] for r in val]
    pred = model.predict(X)
    print("\n=== VULN RISK REGRESSOR ===")
    print("MAE:", mean_absolute_error(y, pred))
    print("R2 :", r2_score(y, pred))

def main():
    # run only what exists
    if Path("ml/models/intent_tfidf/model.joblib").exists() and Path("ml/data/intent_val.jsonl").exists():
        eval_intent()
    else:
        print("Intent eval skipped (missing model or val file).")

    if Path("ml/models/sector_tfidf/model.joblib").exists() and Path("ml/data/sector_val.jsonl").exists():
        eval_sector()
    else:
        print("Sector eval skipped (missing model or val file).")

    if Path("ml/models/vuln_risk/model.joblib").exists() and Path("ml/data/vuln_val.jsonl").exists():
        eval_vuln()
    else:
        print("Vuln eval skipped (missing model or val file).")

if __name__ == "__main__":
    main()
