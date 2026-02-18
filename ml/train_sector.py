import json
from pathlib import Path
import joblib
import numpy as np
import warnings
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.metrics import classification_report

SECTOR_LABELS = [
    "banking", "upi", "railways", "power_grid", "telecom",
    "airport", "ports", "oil", "other"
]

DATA_TRAIN = Path("ml/data/train.jsonl")
DATA_VAL   = Path("ml/data/val.jsonl")
OUT_DIR    = Path("ml/models/sector_tfidf")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def load_jsonl(fp: Path):
    if not fp.exists():
        raise FileNotFoundError(f"Missing file: {fp}")
    rows = []
    with fp.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Bad JSON on line {i} in {fp}: {e}") from e
    return rows

def multi_hot(sectors_list):
    idx = {s: i for i, s in enumerate(SECTOR_LABELS)}
    y = np.zeros((len(sectors_list), len(SECTOR_LABELS)), dtype=np.int32)

    for r, sectors in enumerate(sectors_list):
        if not sectors:
            y[r, idx["other"]] = 1
            continue

        hit = False
        for s in sectors:
            if s in idx:
                y[r, idx[s]] = 1
                hit = True

        if not hit:
            y[r, idx["other"]] = 1

    return y

def warn_zero_positive_labels(y_mh):
    positives = y_mh.sum(axis=0)
    missing = [SECTOR_LABELS[i] for i, c in enumerate(positives) if c == 0]
    if missing:
        print(f"[WARN] These sector labels have 0 positive samples in TRAIN: {missing}")
        print("       Add at least 2 examples each for better training/demo.")

def main():
    train = load_jsonl(DATA_TRAIN)
    val   = load_jsonl(DATA_VAL)

    X_train = [r["text"] for r in train]
    y_train = multi_hot([r.get("sectors", []) for r in train])

    X_val = [r["text"] for r in val]
    y_val = multi_hot([r.get("sectors", []) for r in val])

    warn_zero_positive_labels(y_train)

    vec = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=1,
        max_features=60000,
        sublinear_tf=True
    )

    Xtr = vec.fit_transform(X_train)
    Xva = vec.transform(X_val)

    # Balanced helps recall/confidence when you have few positives per sector
    base = LogisticRegression(max_iter=2000, class_weight="balanced")
    clf = OneVsRestClassifier(base)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=UserWarning)
        clf.fit(Xtr, y_train)

    preds = clf.predict(Xva)
    print(classification_report(y_val, preds, target_names=SECTOR_LABELS, zero_division=0))

    joblib.dump(
        {"vectorizer": vec, "clf": clf, "sector_labels": SECTOR_LABELS},
        OUT_DIR / "model.joblib"
    )
    print(f"Saved -> {OUT_DIR / 'model.joblib'}")

if __name__ == "__main__":
    main()
