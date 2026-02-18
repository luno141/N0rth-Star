# ml/train_sector.py
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

from joblib import dump
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

DATA_TRAIN = Path("ml/data/sector_train.jsonl")
DATA_VAL = Path("ml/data/sector_val.jsonl")
OUT_DIR = Path("ml/models/sector_tfidf")
OUT_PATH = OUT_DIR / "model.joblib"

def load_jsonl(fp: Path) -> Tuple[List[str], List[str]]:
    if not fp.exists():
        raise FileNotFoundError(f"Missing file: {fp}")
    X, y = [], []
    with fp.open("r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            X.append(row["text"])
            y.append(row["label"])
    return X, y

def main():
    X_train, y_train = load_jsonl(DATA_TRAIN)
    X_val, y_val = load_jsonl(DATA_VAL)

    print(f"[Sector] Loaded train={len(X_train)} val={len(X_val)} from jsonl")

    vec = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_features=40000,
        sublinear_tf=True
    )

    Xtr = vec.fit_transform(X_train)
    Xva = vec.transform(X_val)

    clf = LogisticRegression(
        solver="saga",
        max_iter=3000,
        class_weight="balanced",
        n_jobs=None,
        random_state=42
    )
    clf.fit(Xtr, y_train)

    pred = clf.predict(Xva)
    print(classification_report(y_val, pred, zero_division=0))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    bundle = {
        "vectorizer": vec,
        "clf": clf,
        "labels": sorted(list(set(y_train)))
    }
    dump(bundle, OUT_PATH)
    print(f"Saved -> {OUT_PATH}")

if __name__ == "__main__":
    main()
