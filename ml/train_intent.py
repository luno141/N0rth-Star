import json
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

DATA_TRAIN = Path("ml/data/train.jsonl")
DATA_VAL   = Path("ml/data/val.jsonl")
OUT_DIR    = Path("ml/models/intent_tfidf")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Keep canonical labels for consistent reporting
INTENT_LABELS = ["leak", "planning", "claim", "discussion", "irrelevant"]

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

def warn_missing_labels(y, label_list, split_name="train"):
    present = set(y)
    missing = [l for l in label_list if l not in present]
    if missing:
        print(f"[WARN] Missing intent labels in {split_name}: {missing}")

def main():
    train = load_jsonl(DATA_TRAIN)
    val   = load_jsonl(DATA_VAL)

    X_train = [r["text"] for r in train]
    y_train = [r["intent"] for r in train]

    X_val = [r["text"] for r in val]
    y_val = [r["intent"] for r in val]

    warn_missing_labels(y_train, INTENT_LABELS, "train")
    warn_missing_labels(y_val, INTENT_LABELS, "val")

    vec = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=1,
        max_features=50000,
        sublinear_tf=True
    )

    Xtr = vec.fit_transform(X_train)
    Xva = vec.transform(X_val)

    # NOTE: n_jobs removed (new sklearn warns it has no effect)
    clf = LogisticRegression(max_iter=2000)
    clf.fit(Xtr, y_train)

    preds = clf.predict(Xva)
    print(classification_report(y_val, preds, zero_division=0))

    joblib.dump(
        {"vectorizer": vec, "clf": clf, "intent_labels": INTENT_LABELS},
        OUT_DIR / "model.joblib"
    )
    print(f"Saved -> {OUT_DIR / 'model.joblib'}")

if __name__ == "__main__":
    main()
