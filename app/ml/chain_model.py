"""Markov chain transition model for privilege escalation predictions."""
import logging
from collections import defaultdict

from app.agents.priv_escalation import ESCALATION_ORDER
from app.models import Prediction

log = logging.getLogger(__name__)

ALL_STATES = ["Start"] + ESCALATION_ORDER + ["End"]


class ChainModel:
    def __init__(self) -> None:
        self.transitions: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._init_fallback_prior()

    def _init_fallback_prior(self) -> None:
        """Forward transitions along ESCALATION_ORDER get weight 3, others weight 1."""
        self.transitions.clear()
        for idx, s in enumerate(ESCALATION_ORDER):
            for next_s in ESCALATION_ORDER + ["End"]:
                if next_s == "End":
                    self.transitions[s][next_s] = 1.0
                else:
                    next_idx = ESCALATION_ORDER.index(next_s)
                    if next_idx > idx:
                        self.transitions[s][next_s] = 3.0
                    else:
                        self.transitions[s][next_s] = 1.0

    def fit(self, chains: list[list[str]]) -> None:
        if not chains or len(chains) < 5:
            self._init_fallback_prior()
            # If some chains exist, boost observed transitions
            for ch in (chains or []):
                for a, b in zip(ch[:-1], ch[1:]):
                    self.transitions[a][b] += 2.0
            return

        counts: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        # Add-one smoothing
        for s1 in ALL_STATES:
            for s2 in ALL_STATES:
                if s2 != "Start":
                    counts[s1][s2] = 1.0

        for ch in chains:
            if not ch:
                continue
            full = ["Start"] + ch + ["End"]
            for a, b in zip(full[:-1], full[1:]):
                counts[a][b] += 1.0

        self.transitions = counts

    def predict(self, state: str) -> Prediction | None:
        if state not in self.transitions:
            return None

        candidates = {s: w for s, w in self.transitions[state].items() if s != "Start"}
        total = sum(candidates.values())
        if total == 0:
            return None

        probs = {s: w / total for s, w in candidates.items()}
        # Pick the most likely state
        best_state, best_prob = max(probs.items(), key=lambda kv: kv[1])
        return Prediction(next_state=best_state, probability=round(best_prob, 2))
