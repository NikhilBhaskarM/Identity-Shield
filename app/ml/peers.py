"""Peer group clustering and peer action rarity estimation."""
import logging
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans

log = logging.getLogger(__name__)


class PeerModel:
    def __init__(self) -> None:
        self.fitted: bool = False
        self.identity_cluster: dict[str, int] = {}
        self.cluster_action_counts: dict[int, Counter] = {}
        self.cluster_total_actions: dict[int, int] = {}

    def fit(self, df: pd.DataFrame) -> bool:
        if df is None or df.empty:
            return False

        identities = df["identity_id"].unique()
        n_ident = len(identities)
        if n_ident < 3:
            return False

        try:
            # Build profile per identity: privilege, action frequencies
            top_actions = df["action"].value_counts().head(20).index.tolist()
            profiles = []
            for ident in identities:
                sub = df[df["identity_id"] == ident]
                priv = float(sub["privilege_level"].max() if "privilege_level" in sub else 1.0)
                act_counts = sub["action"].value_counts().to_dict()
                vec = [priv] + [float(act_counts.get(a, 0)) for a in top_actions]
                profiles.append(vec)

            X = np.array(profiles, dtype=float)
            k = min(5, n_ident)
            kmeans = KMeans(n_clusters=k, n_init=10, random_state=42)
            labels = kmeans.fit_predict(X)

            self.identity_cluster = {ident: int(lbl) for ident, lbl in zip(identities, labels)}
            self.cluster_action_counts = {i: Counter() for i in range(k)}
            self.cluster_total_actions = {i: 0 for i in range(k)}

            for _, row in df.iterrows():
                ident = row["identity_id"]
                act = row["action"]
                c = self.identity_cluster.get(ident)
                if c is not None:
                    self.cluster_action_counts[c][act] += 1
                    self.cluster_total_actions[c] += 1

            self.fitted = True
            return True
        except Exception:
            log.exception("PeerModel fitting failed")
            return False

    def peer_rarity(self, identity_id: str, action: str) -> float:
        if not self.fitted:
            return 1.0
        c = self.identity_cluster.get(identity_id)
        if c is None:
            return 1.0
        total = self.cluster_total_actions.get(c, 0)
        if total == 0:
            return 1.0
        count = self.cluster_action_counts[c].get(action, 0)
        freq = count / total
        return float(max(0.0, min(1.0, 1.0 - freq)))
