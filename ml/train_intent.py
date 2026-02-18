# ml/train_intent.py
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Dict, Any

from joblib import dump
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.metrics import classification_report


DATA_TRAIN = Path("ml/data/intent_train.jsonl")
DATA_VAL = Path("ml/data/intent_val.jsonl")
OUT_DIR = Path("ml/models/intent_tfidf")
OUT_MODEL = OUT_DIR / "model.joblib"

ALL_LABELS = ["planning", "claim", "leak", "discussion", "irrelevant"]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    train_rows = load_jsonl(DATA_TRAIN)
    val_rows = load_jsonl(DATA_VAL)

    X_train = [r["text"] for r in train_rows]
    y_train = [r["label"] for r in train_rows]

    X_val = [r["text"] for r in val_rows]
    y_val = [r["label"] for r in val_rows]

    print(f"[Intent] Loaded train={len(X_train)} val={len(X_val)} from jsonl")

    missing = sorted(list(set(ALL_LABELS) - set(y_val)))
    if missing:
        print(f"[WARN] Missing intent labels in val: {missing}")

    # ✅ Most compatible multiclass setup across sklearn versions:
    # TF-IDF -> One-vs-Rest Logistic Regression (liblinear)
    base_lr = LogisticRegression(
        max_iter=3000,
        class_weight="balanced",
        solver="liblinear"
    )

    clf = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            sublinear_tf=True,
            strip_accents="unicode"
        )),
        ("clf", OneVsRestClassifier(base_lr))
    ])

    clf.fit(X_train, y_train)

    pred = clf.predict(X_val)
    print(classification_report(y_val, pred, labels=ALL_LABELS, zero_division=0))

    dump({
        "pipeline": clf,
        "labels": ALL_LABELS,
        "task": "intent"
    }, OUT_MODEL)

    print(f"Saved -> {OUT_MODEL}")


if __name__ == "__main__":
    main()
