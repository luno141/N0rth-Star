import joblib
import numpy as np
from pathlib import Path

INTENT_MODEL_PATH = Path("ml/models/intent_tfidf/model.joblib")
SECTOR_MODEL_PATH = Path("ml/models/sector_tfidf/model.joblib")
VULN_MODEL_PATH   = Path("ml/models/vuln_risk/model.joblib")

class NorthStarModels:
    def __init__(
        self,
        intent_path=INTENT_MODEL_PATH,
        sector_path=SECTOR_MODEL_PATH,
        vuln_path=VULN_MODEL_PATH
    ):
        self.intent_bundle = joblib.load(str(intent_path))
        self.sector_bundle = joblib.load(str(sector_path))

        self.intent_vec = self.intent_bundle["vectorizer"]
        self.intent_clf = self.intent_bundle["clf"]

        self.sector_vec = self.sector_bundle["vectorizer"]
        self.sector_clf = self.sector_bundle["clf"]
        self.sector_labels = self.sector_bundle["sector_labels"]

        # Vuln model is optional (so you can ship even without dataset)
        self.vuln_bundle = None
        if vuln_path.exists():
            self.vuln_bundle = joblib.load(str(vuln_path))

    def predict_intent(self, text: str):
        X = self.intent_vec.transform([text])
        proba = self.intent_clf.predict_proba(X)[0]
        labels = self.intent_clf.classes_
        i = int(np.argmax(proba))
        return {"label": str(labels[i]), "confidence": float(proba[i])}

    def predict_sectors(
        self,
        text: str,
        threshold: float = 0.35,
        top_k: int = 1,
        margin: float = 0.10,
    ):
        """
        Multi-label model, but product default is ONE sector.

        Rules:
        - Apply threshold
        - Drop 'other' if any real sector exists
        - Default: top 1 sector
        - If top_k > 1, allow additional sectors only if within `margin` of top score
        """
        X = self.sector_vec.transform([text])
        proba = self.sector_clf.predict_proba(X)[0]

        scored = [{"label": label, "confidence": float(p)} for label, p in zip(self.sector_labels, proba)]
        scored.sort(key=lambda x: x["confidence"], reverse=True)

        out = [x for x in scored if x["confidence"] >= threshold]

        real = [x for x in out if x["label"] != "other"]
        if real:
            out = real

        if not out:
            return [scored[0]]

        top = out[0]
        if top_k <= 1:
            return [top]

        kept = [top]
        for x in out[1:]:
            if x["confidence"] >= top["confidence"] - margin:
                kept.append(x)
            if len(kept) >= top_k:
                break
        return kept

    # -----------------------------
    # Vulnerability risk prediction
    # -----------------------------

    def _normalize_vuln_features(self, d: dict) -> dict:
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

    def vuln_risk_heuristic(self, features: dict) -> dict:
        """
        Fallback when you don't have a trained risk model yet.
        Returns score 0-100 + explainability reasons.
        """
        f = self._normalize_vuln_features(features)
        score = 0.0
        reasons = []

        cvss = f["cvss"]
        score += min(40.0, (cvss / 10.0) * 40.0)
        if cvss >= 9:
            reasons.append("High CVSS")

        if f["internet_exposed"]:
            score += 20.0
            reasons.append("Internet exposed")

        if f["known_exploit"]:
            score += 20.0
            reasons.append("Known exploit in the wild")

        if not f["auth_required"]:
            score += 8.0
            reasons.append("No auth required")

        patch_age = f["patch_age_days"]
        if patch_age >= 30:
            score += 7.0
            reasons.append("Patch overdue (30+ days)")
        elif patch_age >= 7:
            score += 4.0
            reasons.append("Patch pending (7+ days)")

        crit = f["asset_criticality"]
        if crit == "high":
            score += 10.0
            reasons.append("High critical asset")
        elif crit == "medium":
            score += 6.0
            reasons.append("Medium critical asset")
        elif crit == "low":
            score += 3.0
            reasons.append("Low critical asset")

        env = f["env"]
        if env == "prod":
            score += 5.0
            reasons.append("Production environment")

        score = float(max(0.0, min(100.0, score)))
        return {"score": score, "method": "heuristic", "reasons": reasons}

    def vuln_risk_predict(self, features: dict) -> dict:
        """
        If trained model exists: use it.
        Else: fallback heuristic.
        """
        if self.vuln_bundle is None:
            return self.vuln_risk_heuristic(features)

        f = self._normalize_vuln_features(features)
        vec = self.vuln_bundle["vectorizer"]
        model = self.vuln_bundle["model"]
        X = vec.transform([f])
        pred = float(model.predict(X)[0])
        pred = float(max(0.0, min(100.0, pred)))
        return {"score": pred, "method": "ml", "reasons": []}

    def predict_all(self, text: str, vuln_features: dict | None = None):
        intent = self.predict_intent(text)
        sectors = self.predict_sectors(text, threshold=0.35, top_k=1, margin=0.10)

        out = {"intent": intent, "sectors": sectors}

        if vuln_features is not None:
            out["vuln_risk"] = self.vuln_risk_predict(vuln_features)

        return out
