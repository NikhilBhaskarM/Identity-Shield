"""Behavior Baseline Agent (ML): Isolation Forest anomaly detection per session."""
import pandas as pd

from app.agents.base import Agent
from app.ml.anomaly import AnomalyModel
from app.ml.features import numeric_columns, session_features
from app.models import Signal


class BaselineMLAgent(Agent):
    name: str = "baseline_ml"
    pattern: str = "ML"

    def __init__(self) -> None:
        super().__init__()
        self.scores: dict[str, float] = {}
        self.anomaly_model = AnomalyModel()

    def detect(self, events: pd.DataFrame) -> list[Signal]:
        signals: list[Signal] = []
        self.scores = {}
        if events is None or events.empty:
            return signals

        feat_df = session_features(events)
        if feat_df.empty:
            return signals

        num_cols = [c for c in numeric_columns() if c in feat_df.columns]
        X = feat_df[num_cols]

        # Fit on benign sessions if labels exist
        if "label" in events.columns and events["label"].dropna().any():
            benign_sessions = set(
                events[events["label"].astype(str).str.lower().isin(["benign", "none"])]["session_id"].unique()
            )
            train_idx = [s for s in feat_df.index if s in benign_sessions]
            X_train = X.loc[train_idx] if len(train_idx) >= 20 else X
        else:
            X_train = X

        if not self.anomaly_model.fit(X_train):
            return signals

        scores = self.anomaly_model.score(X)
        events_by_sess = events.groupby("session_id")

        for sess_id, score in zip(feat_df.index, scores):
            self.scores[str(sess_id)] = float(score)
            if score >= 0.6:
                sess_events = events_by_sess.get_group(sess_id)
                ident = str(feat_df.loc[sess_id, "identity_id"])
                eids = [str(e) for e in sess_events["event_id"].head(5)]
                last_t = pd.to_datetime(sess_events["timestamp"], utc=True).max()

                signals.append(Signal(
                    pattern=self.pattern,
                    severity=round(float(score), 2),
                    identity_id=ident,
                    session_id=str(sess_id),
                    agent=self.name,
                    reason=f"Session behavior is unusual compared with normal activity (anomaly score {score:.2f}).",
                    evidence_event_ids=eids,
                    mitre=[],
                    timestamp=last_t,
                ))

        return signals
