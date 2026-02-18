import json
from pathlib import Path
import joblib
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, r2_score

DATA_TRAIN = Path("ml/data/vuln_train.jsonl")
DATA_VAL   = Path("ml/data/vuln_val.jsonl")
OUT_DIR    = Path("ml/models/vuln_risk")
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

def normalize_features(d: dict) -> dict:
    out = {}
    out["cvss"] = float(d.get("cvss", 0.0))
    out["internet_exposed"] = bool(d.get("internet_exposed", False))
    out["known_exploit"] = bool(d.get("known_exploit", False))
    out["auth_required"] = bool(d.get("auth_required", False))
    out["patch_age_days"] = float(d.get("patch_age_days", 0.0))
    out["vuln_age_days"] = float(d.get("vuln_age_days", 0.0))
    out["asset_criticality"] = str(d.get("asset_criticality", "unknown")).lower()
    out["env"] = str(d.get("env", "unknown")).lower()
    out["attack_surface"] = str(d.get("attack_surface", "unknown")).lower()
    return out

def main():
    train = load_jsonl(DATA_TRAIN)
    val   = load_jsonl(DATA_VAL)

    X_train_dict = [normalize_features(r.get("features", {})) for r in train]
    y_train = np.array([float(r.get("risk", 0.0)) for r in train], dtype=float)

    X_val_dict = [normalize_features(r.get("features", {})) for r in val]
    y_val = np.array([float(r.get("risk", 0.0)) for r in val], dtype=float)

    vec = DictVectorizer(sparse=True)
    Xtr = vec.fit_transform(X_train_dict)
    Xva = vec.transform(X_val_dict)

    model = RandomForestRegressor(
        n_estimators=300,
        random_state=42,
        min_samples_leaf=2
    )
    model.fit(Xtr, y_train)

    preds = model.predict(Xva)
    mae = mean_absolute_error(y_val, preds)
    r2 = r2_score(y_val, preds) if len(y_val) >= 2 else float("nan")

    print(f"Vuln Risk Model | MAE: {mae:.2f} | R2: {r2}")

    joblib.dump(
        {"vectorizer": vec, "model": model},
        OUT_DIR / "model.joblib"
    )
    print(f"Saved -> {OUT_DIR / 'model.joblib'}")

if __name__ == "__main__":
    main()
