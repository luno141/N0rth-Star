# ml/infer.py
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import math
from joblib import load


INTENT_MODEL_PATH = Path("ml/models/intent_tfidf/model.joblib")
SECTOR_MODEL_PATH = Path("ml/models/sector_tfidf/model.joblib")
VULN_MODEL_PATH = Path("ml/models/vuln_risk/model.joblib")


def _softmax(xs: List[float]) -> List[float]:
    if not xs:
        return []
    m = max(xs)
    exps = [math.exp(x - m) for x in xs]
    s = sum(exps) or 1.0
    return [e / s for e in exps]


def _sigmoid(x: float) -> float:
    # stable-ish sigmoid
    if x >= 0:
        z = math.exp(-x)
        return 1 / (1 + z)
    z = math.exp(x)
    return z / (1 + z)


def _normalize_probs_fallback(scores: List[float]) -> List[float]:
    """
    If model doesn't expose predict_proba, we try:
      - for multiclass: softmax(decision_function)
      - for OVR multilabel: sigmoid(decision_function) then normalize (sum=1)
    We'll just do sigmoid then normalize, works reasonably for OVR too.
    """
    if not scores:
        return []
    ps = [_sigmoid(s) for s in scores]
    s = sum(ps) or 1.0
    return [p / s for p in ps]


def _load_bundle(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing model file: {path}")
    obj = load(path)
    if not isinstance(obj, dict):
        # allow plain pipeline too
        return {"pipeline": obj, "labels": None}
    return obj


def _bundle_to_pipeline(bundle: Dict[str, Any]):
    """
    Supports:
    - New format: {"pipeline": Pipeline, "labels": [...], "task": "..."}
    - Old format: {"vectorizer": vec, "clf": clf, "labels": [...]}
    """
    if "pipeline" in bundle:
        return bundle["pipeline"], bundle.get("labels")

    # legacy
    vec = bundle.get("vectorizer")
    clf = bundle.get("clf")
    labels = bundle.get("labels")
    if vec is None or clf is None:
        raise KeyError(f"Model bundle missing pipeline or legacy keys: {bundle.keys()}")

    class _LegacyPipe:
        def __init__(self, v, c):
            self.v = v
            self.c = c

        def predict(self, texts):
            X = self.v.transform(texts)
            return self.c.predict(X)

        def predict_proba(self, texts):
            X = self.v.transform(texts)
            if hasattr(self.c, "predict_proba"):
                return self.c.predict_proba(X)
            if hasattr(self.c, "decision_function"):
                df = self.c.decision_function(X)
                # df can be shape (n,) for binary, or (n,k)
                return df
            raise AttributeError("No predict_proba/decision_function on legacy clf")

        def decision_function(self, texts):
            X = self.v.transform(texts)
            return self.c.decision_function(X)

    return _LegacyPipe(vec, clf), labels


@dataclass
class _ModelWrap:
    pipe: Any
    labels: List[str]


class NorthStarModels:
    """
    Loads intent + sector + vuln models (torch-free).
    Compatible with both old and new saved formats.
    """

    def __init__(self):
        # intent
        intent_bundle = _load_bundle(INTENT_MODEL_PATH)
        intent_pipe, intent_labels = _bundle_to_pipeline(intent_bundle)
        if not intent_labels:
            # fallback if not present
            intent_labels = intent_bundle.get("classes") or []
        self.intent = _ModelWrap(intent_pipe, list(intent_labels))

        # sector
        sector_bundle = _load_bundle(SECTOR_MODEL_PATH)
        sector_pipe, sector_labels = _bundle_to_pipeline(sector_bundle)
        if not sector_labels:
            sector_labels = sector_bundle.get("classes") or []
        self.sector = _ModelWrap(sector_pipe, list(sector_labels))

        # vuln risk (optional)
        self.vuln_bundle: Optional[Dict[str, Any]] = None
        self.vuln_pipe: Optional[Any] = None
        if VULN_MODEL_PATH.exists():
            vb = _load_bundle(VULN_MODEL_PATH)
            # your vuln trainer likely saved {"pipeline":..., ...} or {"model": ...}
            if "pipeline" in vb:
                self.vuln_pipe = vb["pipeline"]
            elif "model" in vb:
                self.vuln_pipe = vb["model"]
            else:
                # allow joblib dump of estimator itself
                if not isinstance(vb, dict):
                    self.vuln_pipe = vb
                else:
                    # last resort: try any key
                    self.vuln_pipe = next(iter(vb.values()))
            self.vuln_bundle = vb

    # -------- intent --------
    def _predict_single_label(self, wrap: _ModelWrap, text: str) -> Tuple[str, float, List[Tuple[str, float]]]:
        text = text or ""
        labels = wrap.labels

        # 1) try predict_proba
        proba = None
        if hasattr(wrap.pipe, "predict_proba"):
            try:
                proba = wrap.pipe.predict_proba([text])
            except Exception:
                proba = None

        if proba is not None:
            # sklearn can return ndarray-like
            row = list(proba[0]) if hasattr(proba, "__len__") else []
            if labels and len(row) == len(labels):
                pairs = list(zip(labels, row))
                pairs.sort(key=lambda x: x[1], reverse=True)
                top = pairs[0]
                return top[0], float(top[1]), [(k, float(v)) for k, v in pairs]

        # 2) decision_function -> normalize
        if hasattr(wrap.pipe, "decision_function"):
            df = wrap.pipe.decision_function([text])
            # df can be (k,) or (1,k)
            if hasattr(df, "__len__"):
                if hasattr(df[0], "__len__"):
                    scores = list(df[0])
                else:
                    # binary case shape (1,) maybe
                    scores = [float(df[0])]
            else:
                scores = [float(df)]

            # if labels length matches, use that, else fallback label "unknown"
            if not labels:
                labels = [f"class_{i}" for i in range(len(scores))]
                wrap.labels = labels

            if len(scores) != len(labels):
                # safest alignment
                labels = labels[: len(scores)]

            probs = _normalize_probs_fallback([float(s) for s in scores])
            pairs = list(zip(labels, probs))
            pairs.sort(key=lambda x: x[1], reverse=True)
            top = pairs[0]
            return top[0], float(top[1]), [(k, float(v)) for k, v in pairs]

        # 3) plain predict
        y = wrap.pipe.predict([text])[0]
        return str(y), 0.55, [(str(y), 0.55)]

    # -------- sector --------
    def _predict_top_sectors(self, text: str, top_k: int = 3) -> List[Dict[str, float]]:
        label, conf, all_pairs = self._predict_single_label(self.sector, text)

        # for OVR sector model, "all_pairs" are already sorted probs.
        out = []
        for lab, p in all_pairs[:max(1, top_k)]:
            out.append({"label": lab, "confidence": float(p)})
        return out

    # -------- vuln risk --------
    def vuln_risk_predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Expects dict like:
          cvss (float), internet_exposed (bool), asset_criticality (low/medium/high),
          patch_age_days (int), known_exploit (bool), env (dev/stage/prod), auth_required (bool), attack_surface (web/api/etc)
        Your train_vuln.py defines the feature handling. Here we just pass through.
        """
        if self.vuln_pipe is None:
            return {"score": 0.0, "method": "none", "reasons": ["No vuln model loaded"]}

        # Many sklearn pipelines accept a list[dict] (DictVectorizer inside), or DataFrame.
        try:
            pred = self.vuln_pipe.predict([features])[0]
            return {"score": float(pred), "method": "ml", "reasons": []}
        except Exception as e:
            # fallback: if your model expects ordered numeric vector, you'd adapt here
            return {"score": 0.0, "method": "error", "reasons": [f"vuln predict failed: {e}"]}

    # -------- combined --------
    def predict_all(self, text: str, vuln_features: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        intent_label, intent_conf, _ = self._predict_single_label(self.intent, text)
        sectors = self._predict_top_sectors(text, top_k=3)

        out: Dict[str, Any] = {
            "intent": {"label": intent_label, "confidence": float(intent_conf)},
            "sectors": sectors
        }

        if vuln_features is not None:
            out["vuln_risk"] = self.vuln_risk_predict(vuln_features)

        return out
