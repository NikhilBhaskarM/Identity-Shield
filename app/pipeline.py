"""Orchestrator and end-to-end detection pipeline."""
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from pathlib import Path
import time
import networkx as nx
import pandas as pd

from app import audit, config, store, trace
from app.agents.baseline_ml import BaselineMLAgent
from app.agents.dormant import DormantAccountAgent
from app.agents.impossible_travel import ImpossibleTravelAgent
from app.agents.priv_escalation import PrivEscalationAgent
from app.agents.token_abuse import TokenAbuseAgent
from app.agents.unusual_api import ApiAnomalyAgent
from app.correlate.graph import blast_radius, build_graph
from app.correlate.sessions import assign_sessions
from app.decision.explain import build_reasons, evidence_ids, mitre_tags
from app.decision.respond import auto_apply, recommend
from app.decision.scoring import counterfactuals, score_session
from app.evaluation import compute_metrics
from app.ingest.enrich import enrich
from app.ingest.loaders import load_cloudtrail, load_labels, load_metadata, load_okta
from app.ingest.normalize import normalize_all
from app.ml.chain_model import ChainModel
from app.models import Alert, Metrics, Signal
from app.sample_data import generate
from app.simulator import get_simulator
from app.utils import to_band

log = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    events: pd.DataFrame
    graph: nx.MultiDiGraph
    alerts: list[Alert]
    metrics: Metrics
    status: str  # "ok" | "degraded" | "failed"
    detail: str
    data_mode: str  # "official" | "sample" | "input" | ...
    signals: list[Signal] = field(default_factory=list)
    step_errors: list[str] = field(default_factory=list)
    timings_ms: dict[str, float] = field(default_factory=dict)


def get_identity_rows(result: PipelineResult) -> list[dict]:
    if result is None or result.events is None or result.events.empty:
        return []

    alerts_by_id: dict[str, list[Alert]] = defaultdict(list)
    for a in result.alerts:
        alerts_by_id[a.identity_id].append(a)

    ident_priv = result.events.groupby("identity_id")["privilege_level"].max().to_dict()

    rows: list[dict] = []
    all_identities = sorted(list(result.events["identity_id"].unique()))
    for ident in all_identities:
        ident_alerts = alerts_by_id.get(ident, [])
        max_risk = max([a.risk for a in ident_alerts], default=0.0)
        priv = int(ident_priv.get(ident, 1))
        radius = blast_radius(result.graph, ident)
        rows.append({
            "identity_id": ident,
            "risk": round(max_risk, 1),
            "alerts": len(ident_alerts),
            "privilege_level": priv,
            "blast_radius": radius,
        })

    rows.sort(key=lambda r: (r["risk"], r["blast_radius"]), reverse=True)
    return rows


def run_pipeline(use_sample: bool | None = None, input_mode: str | None = None) -> PipelineResult:
    timings_ms: dict[str, float] = {}
    step_errors: list[str] = []
    t_start = time.perf_counter()

    # Step 1: Ingestion
    t0 = time.perf_counter()
    ct_records: list[dict] = []
    okta_records: list[dict] = []
    metadata: dict = {}
    labels: dict = {}
    total_skipped = 0
    data_mode = "dataset"

    try:
        with trace.step("ingestion", "Loading CloudTrail and Okta files") as s:
            if input_mode == "only":
                data_mode = "input"
                input_ct_dir = getattr(config, "INPUT_DIR", config.DATA_DIR / "input") / "cloudtrail"
                input_okta_dir = getattr(config, "INPUT_DIR", config.DATA_DIR / "input") / "okta"
                ct_records, ct_skipped = load_cloudtrail(input_ct_dir)
                okta_records, okta_skipped = load_okta(input_okta_dir)
                total_skipped = ct_skipped + okta_skipped
                if not ct_records and not okta_records:
                    s.output({"records": {"cloudtrail": 0, "okta": 0}, "skipped": 0}, "No input data found")
                    return PipelineResult(
                        events=pd.DataFrame(),
                        graph=nx.MultiDiGraph(),
                        alerts=[],
                        metrics=Metrics(),
                        status="failed",
                        detail="No input data. Add data on the Input page first.",
                        data_mode="input",
                        step_errors=["No input data"],
                    )
            else:
                def _has_data_files(folder: Path) -> bool:
                    if not folder.is_dir():
                        return False
                    return any(
                        f.is_file() and f.name != ".gitkeep" and not f.name.startswith(".")
                        for f in folder.iterdir()
                    )

                official_has_files = (
                    _has_data_files(config.RAW_CLOUDTRAIL) or _has_data_files(config.RAW_OKTA)
                )
                if use_sample is True or (use_sample is None and not official_has_files and config.USE_SAMPLE_IF_NO_DATA):
                    base_mode = "sample"
                    target_dir = config.SAMPLE_DIR
                    if not target_dir.is_dir() or not (target_dir / "cloudtrail.json").exists():
                        generate(target_dir)
                    ct_records, ct_s = load_cloudtrail(target_dir)
                    okta_records, ok_s = load_okta(target_dir)
                    metadata = load_metadata(target_dir)
                    labels = load_labels(target_dir)
                    total_skipped += ct_s + ok_s
                else:
                    base_mode = "official"
                    ct_records, ct_s = load_cloudtrail(config.RAW_CLOUDTRAIL)
                    okta_records, ok_s = load_okta(config.RAW_OKTA)
                    metadata = load_metadata(config.METADATA_DIR)
                    labels = load_labels(config.LABELS_DIR)
                    total_skipped += ct_s + ok_s

                if input_mode == "merge":
                    data_mode = f"{base_mode}+input"
                    input_ct_dir = getattr(config, "INPUT_DIR", config.DATA_DIR / "input") / "cloudtrail"
                    input_okta_dir = getattr(config, "INPUT_DIR", config.DATA_DIR / "input") / "okta"
                    in_ct, in_ct_s = load_cloudtrail(input_ct_dir)
                    in_ok, in_ok_s = load_okta(input_okta_dir)
                    ct_records.extend(in_ct)
                    okta_records.extend(in_ok)
                    total_skipped += in_ct_s + in_ok_s
                else:
                    data_mode = base_mode

            s.output(
                {"records": {"cloudtrail": len(ct_records), "okta": len(okta_records)}, "skipped": total_skipped},
                f"Loaded {len(ct_records)} CT and {len(okta_records)} Okta records"
            )
    except Exception as exc:
        log.exception("Ingestion step failed")
        return PipelineResult(
            events=pd.DataFrame(), graph=nx.MultiDiGraph(), alerts=[], metrics=Metrics(),
            status="failed", detail=f"Ingestion failed: {exc}", data_mode=data_mode,
            step_errors=[f"Ingestion error: {exc}"]
        )
    timings_ms["ingestion"] = round((time.perf_counter() - t0) * 1000, 1)

    # Step 2: Normalization
    t0 = time.perf_counter()
    try:
        with trace.step("normalization", "Mapping both formats to one schema") as s:
            df, norm_skipped = normalize_all(ct_records, okta_records)
            total_skipped += norm_skipped
            if labels and "label" in df.columns:
                for idx, eid in enumerate(df["event_id"]):
                    if eid in labels:
                        df.at[idx, "label"] = labels[eid]
            s.output(
                {"events": len(df), "skipped": total_skipped, "identities": int(df["identity_id"].nunique()) if not df.empty else 0},
                f"Normalized {len(df)} events ({df['identity_id'].nunique() if not df.empty else 0} identities)"
            )
            if df.empty:
                return PipelineResult(
                    events=df, graph=nx.MultiDiGraph(), alerts=[], metrics=Metrics(),
                    status="failed", detail="No events after normalization", data_mode=data_mode,
                    step_errors=["Empty data after normalization"]
                )
    except Exception as exc:
        log.exception("Normalization step failed")
        return PipelineResult(
            events=pd.DataFrame(), graph=nx.MultiDiGraph(), alerts=[], metrics=Metrics(),
            status="failed", detail=f"Normalization failed: {exc}", data_mode=data_mode,
            step_errors=[f"Normalization error: {exc}"]
        )
    timings_ms["normalization"] = round((time.perf_counter() - t0) * 1000, 1)

    # Step 3: Enrichment
    t0 = time.perf_counter()
    try:
        with trace.step("enrichment", "Adding geo, privilege and sensitivity") as s:
            df = enrich(df, metadata)
            priv_count = int((df["privilege_level"] >= 3).sum()) if "privilege_level" in df else 0
            s.output({"events": len(df), "privileged_identities": priv_count}, f"Enriched {len(df)} events")
    except Exception as exc:
        log.exception("Enrichment failed")
        step_errors.append(f"Enrichment error: {exc}")
    timings_ms["enrichment"] = round((time.perf_counter() - t0) * 1000, 1)

    # Step 4: Correlation and Sessions
    t0 = time.perf_counter()
    graph = nx.MultiDiGraph()
    try:
        with trace.step("correlation", "Linking Okta sessions to AWS activity") as s:
            df = assign_sessions(df)
            graph = build_graph(df)
            n_sess = int(df["session_id"].nunique())
            s.output(
                {"sessions": n_sess, "graph": {"nodes": len(graph.nodes), "edges": len(graph.edges)}},
                f"Correlated {n_sess} sessions, built graph with {len(graph.nodes)} nodes"
            )
    except Exception as exc:
        log.exception("Correlation/graph failed")
        step_errors.append(f"Correlation error: {exc}")
    timings_ms["correlation"] = round((time.perf_counter() - t0) * 1000, 1)

    # Step 5 - 9: Rule Detectors
    signals: list[Signal] = []

    # 5. impossible_travel
    try:
        with trace.step("impossible_travel", "Evaluating impossible travel") as s:
            sigs = ImpossibleTravelAgent().run(df)
            signals.extend(sigs)
            s.output(
                {"signals": len(sigs), "examples": [{"identity_id": sig.identity_id, "severity": sig.severity, "reason": sig.reason} for sig in sigs[:3]]},
                f"Generated {len(sigs)} impossible travel signals"
            )
    except Exception as exc:
        log.exception("impossible_travel failed")
        step_errors.append(f"impossible_travel error: {exc}")

    # 6. dormant
    try:
        with trace.step("dormant", "Checking dormant accounts") as s:
            sigs = DormantAccountAgent().run(df)
            signals.extend(sigs)
            s.output(
                {"signals": len(sigs), "examples": [{"identity_id": sig.identity_id, "severity": sig.severity, "reason": sig.reason} for sig in sigs[:3]]},
                f"Generated {len(sigs)} dormant account signals"
            )
    except Exception as exc:
        log.exception("dormant failed")
        step_errors.append(f"dormant error: {exc}")

    # 7. priv_escalation
    p3_agent = PrivEscalationAgent()
    try:
        with trace.step("priv_escalation", "Reconstructing privilege escalation chains") as s:
            sigs = p3_agent.run(df)
            signals.extend(sigs)
            s.output(
                {"signals": len(sigs), "examples": [{"identity_id": sig.identity_id, "severity": sig.severity, "reason": sig.reason} for sig in sigs[:3]]},
                f"Generated {len(sigs)} escalation signals"
            )
    except Exception as exc:
        log.exception("priv_escalation failed")
        step_errors.append(f"priv_escalation error: {exc}")

    # 8. api_anomaly
    try:
        with trace.step("api_anomaly", "Flagging unusual API activity") as s:
            sigs = ApiAnomalyAgent().run(df)
            signals.extend(sigs)
            s.output(
                {"signals": len(sigs), "examples": [{"identity_id": sig.identity_id, "severity": sig.severity, "reason": sig.reason} for sig in sigs[:3]]},
                f"Generated {len(sigs)} API anomaly signals"
            )
    except Exception as exc:
        log.exception("api_anomaly failed")
        step_errors.append(f"api_anomaly error: {exc}")

    # 9. token_abuse
    try:
        with trace.step("token_abuse", "Analyzing session and token abuse") as s:
            sigs = TokenAbuseAgent().run(df)
            signals.extend(sigs)
            s.output(
                {"signals": len(sigs), "examples": [{"identity_id": sig.identity_id, "severity": sig.severity, "reason": sig.reason} for sig in sigs[:3]]},
                f"Generated {len(sigs)} token abuse signals"
            )
    except Exception as exc:
        log.exception("token_abuse failed")
        step_errors.append(f"token_abuse error: {exc}")

    # Step 10: Baseline ML Agent
    ml_agent = BaselineMLAgent()
    try:
        if df["session_id"].nunique() < 20:
            trace.skip("baseline_ml", "Not enough sessions to train (<20)")
        else:
            with trace.step("baseline_ml", "Isolation Forest over session features") as s:
                sigs = ml_agent.run(df)
                signals.extend(sigs)
                s.output({"signals": len(sigs)}, f"ML flagged {len(sigs)} anomalous sessions")
    except Exception as exc:
        log.exception("baseline_ml failed")
        step_errors.append(f"baseline_ml error: {exc}")

    # Markov model for escalation prediction
    chain_model = ChainModel()
    try:
        chains = [[step.state for step in steps] for steps in p3_agent.last_chains.values()]
        chain_model.fit(chains)
    except Exception as exc:
        log.exception("ChainModel fit failed")

    # Step 11: Risk Scoring
    alerts: list[Alert] = []
    t0 = time.perf_counter()
    try:
        with trace.step("risk_scoring", "Combining signals x privilege x sensitivity") as s:
            weights = store.get_weights()
            signals_by_sess: dict[str, list[Signal]] = defaultdict(list)
            for sig in signals:
                sess = sig.session_id or f"synthetic:{sig.identity_id}"
                signals_by_sess[sess].append(sig)

            for sess_id, score in ml_agent.scores.items():
                if score >= 0.6 and sess_id not in signals_by_sess:
                    signals_by_sess[sess_id] = []

            events_by_sess = df.groupby("session_id")
            candidate_alerts: list[dict] = []

            for sess_id, sess_sigs in signals_by_sess.items():
                if not sess_sigs and ml_agent.scores.get(sess_id, 0.0) < 0.6:
                    continue

                sess_events = events_by_sess.get_group(sess_id) if sess_id in events_by_sess.groups else pd.DataFrame()
                ident = sess_events["identity_id"].iloc[0] if not sess_events.empty else (
                    sess_sigs[0].identity_id if sess_sigs else "unknown"
                )

                chain_steps = p3_agent.last_chains.get(sess_id, [])
                prediction = chain_model.predict(chain_steps[-1].state) if chain_steps else None
                ml_score = ml_agent.scores.get(sess_id, 0.0)

                risk, conf = score_session(sess_sigs, sess_events, weights, prediction, ml_score)
                c_facts = counterfactuals(sess_sigs, sess_events, weights, prediction, ml_score)
                reasons = build_reasons(sess_sigs)
                mitre = mitre_tags(sess_sigs)
                eids = evidence_ids(sess_sigs, sess_events)
                band = to_band(risk)
                rec_action = recommend(risk)
                radius = blast_radius(graph, ident)

                t_min = sess_events["timestamp"].min() if not sess_events.empty else datetime.now(timezone.utc)
                t_max = sess_events["timestamp"].max() if not sess_events.empty else datetime.now(timezone.utc)
                patterns = sorted(list({sig.pattern for sig in sess_sigs} | ({"ML"} if ml_score >= 0.6 else set())))

                candidate_alerts.append({
                    "identity_id": ident,
                    "session_id": sess_id,
                    "risk": risk,
                    "confidence": conf,
                    "blast_radius": radius,
                    "band": band,
                    "patterns": patterns,
                    "mitre": mitre,
                    "reasons": reasons if reasons else ["Anomalous session behavior detected by baseline ML."],
                    "evidence_event_ids": eids if eids else (list(sess_events["event_id"].head(5)) if not sess_events.empty else []),
                    "chain": chain_steps,
                    "prediction": prediction,
                    "counterfactuals": c_facts,
                    "recommended_action": rec_action,
                    "action_status": "pending",
                    "feedback": None,
                    "first_seen": t_min,
                    "last_seen": t_max,
                })

            candidate_alerts.sort(key=lambda a: (a["risk"], a["blast_radius"]), reverse=True)
            for idx, a_data in enumerate(candidate_alerts, start=1):
                a_data["alert_id"] = f"AL-{idx:04d}"
                alerts.append(Alert(**a_data))

            top_r = alerts[0].risk if alerts else 0.0
            s.output({"alerts": len(alerts), "top_risk": float(top_r)}, f"Scored {len(alerts)} alerts (top risk: {top_r})")
    except Exception as exc:
        log.exception("Risk scoring failed")
        step_errors.append(f"Scoring error: {exc}")
    timings_ms["risk_scoring"] = round((time.perf_counter() - t0) * 1000, 1)

    # Step 12: Explanation
    try:
        with trace.step("explanation", "Writing reasons, counterfactuals and MITRE tags") as s:
            s.output({"alerts_explained": len(alerts)}, f"Generated explanations for {len(alerts)} alerts")
    except Exception as exc:
        log.exception("Explanation failed")
        step_errors.append(f"Explanation error: {exc}")

    # Step 13: Response & Storage
    try:
        with trace.step("response", "Choosing actions (simulator only)") as s:
            store.reset_run_tables()
            store.save_alerts(alerts)
            audit.append("orchestrator", "pipeline_start", f"Mode: {data_mode}, Events: {len(df)}")

            sim = get_simulator()
            applied_count = 0
            pending_count = 0
            for alert in alerts:
                if alert.risk >= 70.0:
                    audit.append("scoring", "high_risk_alert",
                                 f"{alert.alert_id} ({alert.identity_id}): risk {alert.risk} ({alert.band})")
                auto_apply(alert, sim)
                if alert.action_status == "applied":
                    applied_count += 1
                elif alert.action_status == "pending":
                    pending_count += 1

            store.save_alerts(alerts)
            audit.append("orchestrator", "pipeline_end", f"Alerts: {len(alerts)}, Errors: {len(step_errors)}")
            s.output(
                {"applied": applied_count, "pending_approval": pending_count},
                f"Applied {applied_count} actions automatically ({pending_count} pending approval)"
            )
    except Exception as exc:
        log.exception("Response step failed")
        step_errors.append(f"Response error: {exc}")

    # Metrics
    metrics = compute_metrics(
        df, alerts, signals, skipped=total_skipped,
        detection_time_ms=timings_ms.get("detection", 0.0)
    )

    final_status = "failed" if df.empty else ("degraded" if step_errors else "ok")
    detail = "; ".join(step_errors) if step_errors else f"Analyzed {len(df)} events, {len(alerts)} alerts generated."

    return PipelineResult(
        events=df,
        graph=graph,
        alerts=alerts,
        metrics=metrics,
        status=final_status,
        detail=detail,
        data_mode=data_mode,
        signals=signals,
        step_errors=step_errors,
        timings_ms=timings_ms,
    )
