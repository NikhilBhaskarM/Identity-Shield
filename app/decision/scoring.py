"""Risk scoring, counterfactual analysis, and risk decay calculation."""
from collections import defaultdict
import pandas as pd

from app.config import (
    COMBO_BONUS_PER_PATTERN,
    PRIVILEGE_MULTIPLIER,
    RISK_HALF_LIFE_HOURS,
    SENSITIVITY_MULTIPLIER,
    SIGNAL_WEIGHTS,
)
from app.models import Counterfactual, Prediction, Signal


def _compute_risk(patterns_sev: dict[str, float], priv: int, sens: int,
                  pred_prob: float | None, weights: dict) -> float:
    base = 0.0
    for p, sev in patterns_sev.items():
        w = float(weights.get(p, SIGNAL_WEIGHTS.get(p, 20.0)))
        base += w * sev

    ctx_priv = PRIVILEGE_MULTIPLIER.get(priv, 1.0)
    ctx_sens = SENSITIVITY_MULTIPLIER.get(sens, 1.0)
    context = ctx_priv * ctx_sens

    n_patterns = len(patterns_sev)
    combo = 1.0 + (COMBO_BONUS_PER_PATTERN * (n_patterns - 1)) if n_patterns > 1 else 1.0
    chain = 1.0 + pred_prob if pred_prob is not None else 1.0

    raw = base * context * combo * chain
    return min(100.0, max(0.0, round(raw, 1)))


def score_session(signals: list[Signal], session_events: pd.DataFrame, weights: dict,
                  prediction: Prediction | None = None, ml_score: float = 0.0) -> tuple[float, float]:
    patterns_sev: dict[str, float] = defaultdict(float)
    for s in (signals or []):
        if s.pattern != "ML":
            patterns_sev[s.pattern] = max(patterns_sev[s.pattern], float(s.severity))

    if ml_score >= 0.6:
        patterns_sev["ML"] = max(patterns_sev.get("ML", 0.0), float(ml_score))

    if not patterns_sev:
        return 0.0, 0.0

    priv = int(session_events.get("privilege_level", pd.Series([1])).max()) if session_events is not None and not session_events.empty else 1
    sens = int(session_events.get("resource_sensitivity", pd.Series([1])).max()) if session_events is not None and not session_events.empty else 1

    pred_prob = prediction.probability if prediction else None
    risk = _compute_risk(patterns_sev, priv, sens, pred_prob, weights)

    n_ev = len(session_events) if session_events is not None else 1
    n_distinct = len(patterns_sev)
    n_sig = max(1, len(signals or []))
    confidence = min(1.0, n_ev / 10.0) * (n_distinct / n_sig)
    confidence = round(min(1.0, max(0.1, confidence)), 2)

    return risk, confidence


def counterfactuals(signals: list[Signal], session_events: pd.DataFrame, weights: dict,
                    prediction: Prediction | None = None, ml_score: float = 0.0) -> list[Counterfactual]:
    patterns_sev: dict[str, float] = defaultdict(float)
    for s in (signals or []):
        if s.pattern != "ML":
            patterns_sev[s.pattern] = max(patterns_sev[s.pattern], float(s.severity))

    if ml_score >= 0.6:
        patterns_sev["ML"] = max(patterns_sev.get("ML", 0.0), float(ml_score))

    if not patterns_sev:
        return []

    priv = int(session_events.get("privilege_level", pd.Series([1])).max()) if session_events is not None and not session_events.empty else 1
    sens = int(session_events.get("resource_sensitivity", pd.Series([1])).max()) if session_events is not None and not session_events.empty else 1
    pred_prob = prediction.probability if prediction else None

    out: list[Counterfactual] = []
    for p in sorted(patterns_sev.keys()):
        reduced = {k: v for k, v in patterns_sev.items() if k != p}
        # If P3 was removed, chain probability drops
        sub_pred = None if p == "P3" else pred_prob
        c_risk = _compute_risk(reduced, priv, sens, sub_pred, weights)
        out.append(Counterfactual(without=p, risk=c_risk))

    return out


def decayed(risk: float, hours: float, confirmed: bool = False) -> float:
    if confirmed or hours <= 0:
        return float(risk)
    decay_factor = 0.5 ** (hours / RISK_HALF_LIFE_HOURS)
    return round(float(risk) * decay_factor, 1)
