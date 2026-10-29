"""Isolation Forest anomaly detection on session features."""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

MIN_ROWS = 20


class AnomalyModel:
    def __init__(self) -> None:
        self.model: IsolationForest | None = None
        self.columns: list[str] = []

    def fit(self, X: pd.DataFrame) -> bool:
        if X is None or len(X) < MIN_ROWS:
            return False
        self.columns = list(X.columns)
        self.model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
        self.model.fit(X.values)
        return True

    def score(self, X: pd.DataFrame) -> np.ndarray:
        if self.model is None or X is None or X.empty:
            return np.zeros(0 if X is None else len(X))
        raw = -self.model.score_samples(X[self.columns].values)
        lo, hi = float(raw.min()), float(raw.max())
        return (raw - lo) / (hi - lo) if hi > lo else np.zeros(len(raw))
