"""Logistic regression calibrator for session risk scores."""
import logging
import numpy as np
from sklearn.linear_model import LogisticRegression

log = logging.getLogger(__name__)


class Calibrator:
    def __init__(self) -> None:
        self.model: LogisticRegression | None = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> bool:
        if X is None or y is None:
            return False
        if len(y) < 20:
            return False
        unique = np.unique(y)
        if len(unique) < 2:
            return False

        try:
            self.model = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
            self.model.fit(X, y)
            return True
        except Exception:
            log.exception("Calibrator fit failed")
            self.model = None
            return False

    def predict_proba(self, X: np.ndarray) -> np.ndarray | None:
        if self.model is None or X is None or len(X) == 0:
            return None
        try:
            probs = self.model.predict_proba(X)
            return probs[:, 1]
        except Exception:
            log.exception("Calibrator predict failed")
            return None
