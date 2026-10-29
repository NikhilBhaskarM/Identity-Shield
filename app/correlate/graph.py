"""Identity graph construction and analysis using NetworkX MultiDiGraph."""
import logging
import networkx as nx
import pandas as pd

from app.models import GraphEdge, GraphNode, IdentityGraph

log = logging.getLogger(__name__)


def build_graph(events: pd.DataFrame) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    if events is None or events.empty:
        return g

    for _, row in events.iterrows():
        ident = row["identity_id"]
        sess = row["session_id"]
        ip = row["src_ip"]
        action = row["action"]
        key = row["token_id"]
        resource = row["resource"]
        eid = row["event_id"]
        sens = int(row.get("resource_sensitivity") or 1)
        is_attack = bool(row.get("label") and str(row.get("label")).lower() not in {"benign", "none"})

        u_node = f"user:{ident}"
        if not g.has_node(u_node):
            g.add_node(u_node, kind="user", label=ident, risk=0.0)

        if sess:
            s_node = f"session:{sess}"
            if not g.has_node(s_node):
                g.add_node(s_node, kind="session", label=sess, risk=0.0)
            g.add_edge(u_node, s_node, key="login", label="login", event_id=eid, suspicious=is_attack)

            if ip:
                ip_node = f"ip:{ip}"
                if not g.has_node(ip_node):
                    g.add_node(ip_node, kind="ip", label=ip, risk=0.0)
                g.add_edge(s_node, ip_node, key="from_ip", label="from_ip", event_id=eid, suspicious=is_attack)

            if action == "CreateAccessKey":
                target_key = key or f"key-{eid}"
                k_node = f"key:{target_key}"
                if not g.has_node(k_node):
                    g.add_node(k_node, kind="key", label=target_key, risk=0.0)
                g.add_edge(u_node, k_node, key="created_key", label="created_key", event_id=eid, suspicious=is_attack)

            if "Attach" in action or "Put" in action:
                target_policy = resource or "AdministratorAccess"
                p_node = f"policy:{target_policy}"
                if not g.has_node(p_node):
                    g.add_node(p_node, kind="policy", label=target_policy, risk=0.0)
                g.add_edge(u_node, p_node, key="attached", label="attached", event_id=eid, suspicious=is_attack)

            if action in ("AssumeRole", "PassRole"):
                role_name = resource or "AdminRole"
                r_node = f"role:{role_name}"
                if not g.has_node(r_node):
                    g.add_node(r_node, kind="role", label=role_name, risk=0.0)
                g.add_edge(s_node, r_node, key="assumed", label="assumed", event_id=eid, suspicious=is_attack)

            if resource and not ("Attach" in action or "Put" in action or action == "AssumeRole"):
                res_node = f"res:{resource}"
                if not g.has_node(res_node):
                    g.add_node(res_node, kind="resource", label=resource, sensitivity=sens, risk=0.0)
                g.add_edge(s_node, res_node, key="accessed", label="accessed", event_id=eid, suspicious=is_attack)

    return g


def blast_radius(g: nx.MultiDiGraph, identity_id: str) -> int:
    u_node = f"user:{identity_id}"
    if not g.has_node(u_node):
        return 0
    try:
        reachable = nx.descendants(g, u_node) | {u_node}
        # Count reachable sensitive resources (res:* with sensitivity >= 4, or any res:* node)
        res_nodes = [
            n for n in reachable
            if n.startswith("res:") and g.nodes[n].get("sensitivity", 1) >= 4
        ]
        if not res_nodes:
            # Fall back to all reachable res: nodes
            res_nodes = [n for n in reachable if n.startswith("res:")]
        return len(res_nodes)
    except Exception:
        return 0


def escalation_paths(g: nx.MultiDiGraph, identity_id: str) -> list[list[str]]:
    u_node = f"user:{identity_id}"
    if not g.has_node(u_node):
        return []

    target_nodes = [
        n for n in g.nodes
        if ("policy" in n.lower() or "role" in n.lower()) and "admin" in n.lower()
    ]
    paths: list[list[str]] = []
    for tgt in target_nodes:
        if nx.has_path(g, u_node, tgt):
            try:
                for p in nx.all_simple_paths(g, u_node, tgt, cutoff=6):
                    paths.append(p)
                    if len(paths) >= 10:
                        break
            except Exception:
                pass
        if len(paths) >= 10:
            break
    return paths


def identity_subgraph(g: nx.MultiDiGraph, identity_id: str, suspicious_ids: set[str] | None = None) -> IdentityGraph:
    u_node = f"user:{identity_id}"
    suspicious = suspicious_ids or set()

    if not g.has_node(u_node):
        return IdentityGraph(
            identity_id=identity_id,
            nodes=[GraphNode(id=u_node, label=identity_id, kind="user", risk=0.0)],
            edges=[],
            escalation_paths=[]
        )

    # Collect k-hop ego network or descendants + ancestors
    nodes_to_keep = {u_node}
    try:
        nodes_to_keep.update(nx.descendants(g, u_node))
    except Exception:
        pass

    # Cap at 150 nodes
    sub_nodes = list(nodes_to_keep)[:150]
    sub_g = g.subgraph(sub_nodes)

    out_nodes: list[GraphNode] = []
    for n in sub_g.nodes:
        data = sub_g.nodes[n]
        out_nodes.append(GraphNode(
            id=str(n),
            label=str(data.get("label", n)),
            kind=str(data.get("kind", "node")),
            risk=float(data.get("risk", 0.0))
        ))

    out_edges: list[GraphEdge] = []
    for u, v, k, data in sub_g.edges(data=True, keys=True):
        eid = data.get("event_id")
        out_edges.append(GraphEdge(
            source=str(u),
            target=str(v),
            label=str(data.get("label", str(k))),
            event_id=eid,
            suspicious=bool(data.get("suspicious", False) or (eid in suspicious))
        ))

    paths = escalation_paths(g, identity_id)
    return IdentityGraph(
        identity_id=identity_id,
        nodes=out_nodes,
        edges=out_edges,
        escalation_paths=paths
    )
