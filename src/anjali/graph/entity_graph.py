"""Entity graph construction and link analysis.

Money laundering is a *relationship* crime; single-transaction views miss it. This module
builds a directed, weighted multigraph from transactions and customer data, then exposes
the analytics an investigator actually uses: centrality (who is structurally important),
communities (which cluster is a network), shortest paths (how are two subjects connected),
and cycles (did the money come back?).

Everything is pure Python over SQLite — no graph database to operate, no data leaving the
host, which is the point of a local-first compliance tool.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from anjali.analysis.patterns import AnalysisContext, find_cycles
from anjali.core.db import Database
from anjali.core.util import money, normalise_name, slug

D = Decimal


@dataclass
class Node:
    node_id: str
    label: str
    kind: str  # account | customer | country | device | ip
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str  # transfer | ownership | location | shared_access
    weight: float = 1.0
    txn_ids: list[str] = field(default_factory=list)
    amount: Decimal = D("0")
    count: int = 0
    first_ts: str | None = None
    last_ts: str | None = None

    def key(self) -> str:
        return f"{self.src}->{self.dst}:{self.kind}"


class EntityGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, Edge] = {}
        self._out: dict[str, list[str]] = defaultdict(list)
        self._in: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    def add_node(self, node_id: str, label: str, kind: str, **attrs: Any) -> str:
        existing = self.nodes.get(node_id)
        if existing is None:
            self.nodes[node_id] = Node(node_id=node_id, label=label, kind=kind, attrs=dict(attrs))
        else:
            existing.attrs.update({k: v for k, v in attrs.items() if v is not None})
        return node_id

    def add_edge(
        self,
        src: str,
        dst: str,
        kind: str,
        *,
        amount: Decimal | float | None = None,
        txn_id: str | None = None,
        ts: str | None = None,
        weight: float | None = None,
    ) -> None:
        if not src or not dst or src == dst:
            return
        key = f"{src}->{dst}:{kind}"
        edge = self.edges.get(key)
        if edge is None:
            edge = Edge(src=src, dst=dst, kind=kind, weight=0.0)
            self.edges[key] = edge
            self._out[src].append(key)
            self._in[dst].append(key)
        edge.count += 1
        if amount is not None:
            edge.amount += D(str(amount))
        if txn_id and txn_id not in edge.txn_ids:
            edge.txn_ids.append(txn_id)
        if ts:
            edge.first_ts = ts if not edge.first_ts else min(edge.first_ts, ts)
            edge.last_ts = ts if not edge.last_ts else max(edge.last_ts, ts)
        edge.weight = float(weight) if weight is not None else edge.weight + 1.0

    @classmethod
    def from_context(cls, ctx: AnalysisContext) -> EntityGraph:
        g = cls()
        for acct, owner in ctx.account_owner.items():
            g.add_node(f"acct:{acct}", acct, "account")
            g.add_node(f"cust:{owner}", ctx.customers[owner].name if owner in ctx.customers else owner, "customer")
            g.add_edge(f"cust:{owner}", f"acct:{acct}", "ownership", weight=1.0)
        for txn in ctx.transactions:
            if txn.from_account:
                g.add_node(f"acct:{txn.from_account}", txn.from_account, "account")
            if txn.to_account:
                g.add_node(f"acct:{txn.to_account}", txn.to_account, "account")
            if txn.from_account and txn.to_account:
                g.add_edge(
                    f"acct:{txn.from_account}",
                    f"acct:{txn.to_account}",
                    "transfer",
                    amount=txn.amount,
                    txn_id=txn.txn_id,
                    ts=txn.timestamp.isoformat(),
                )
            for acct, name, country in (
                (txn.from_account, txn.from_name, txn.country_from),
                (txn.to_account, txn.to_name, txn.country_to),
            ):
                if acct and name:
                    node = g.add_node(f"name:{normalise_name(name)}", name, "entity")
                    g.add_edge(f"acct:{acct}", node, "held_by", weight=0.5)
                if acct and country:
                    node = g.add_node(f"country:{country.upper()}", country.upper(), "country")
                    g.add_edge(f"acct:{acct}", node, "location", weight=0.3)
            if txn.device_id:
                node = g.add_node(f"dev:{txn.device_id}", txn.device_id, "device")
                for acct in (txn.from_account, txn.to_account):
                    if acct:
                        g.add_edge(f"acct:{acct}", node, "shared_access", weight=0.7)
            if txn.ip_address:
                node = g.add_node(f"ip:{txn.ip_address}", txn.ip_address, "ip")
                for acct in (txn.from_account, txn.to_account):
                    if acct:
                        g.add_edge(f"acct:{acct}", node, "shared_access", weight=0.5)
        return g

    # ------------------------------------------------------------------ #
    # Basic properties
    # ------------------------------------------------------------------ #
    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def neighbours(self, node_id: str, *, direction: str = "both") -> set[str]:
        out: set[str] = set()
        if direction in ("out", "both"):
            out.update(self.edges[k].dst for k in self._out.get(node_id, []))
        if direction in ("in", "both"):
            out.update(self.edges[k].src for k in self._in.get(node_id, []))
        return out

    def degree(self, node_id: str) -> dict[str, int]:
        return {
            "out": len(self._out.get(node_id, [])),
            "in": len(self._in.get(node_id, [])),
            "total": len(self._out.get(node_id, [])) + len(self._in.get(node_id, [])),
        }

    def total_flow(self, node_id: str) -> dict[str, str]:
        inflow = sum((self.edges[k].amount for k in self._in.get(node_id, [])), D("0"))
        outflow = sum((self.edges[k].amount for k in self._out.get(node_id, [])), D("0"))
        return {"in": str(money(inflow)), "out": str(money(outflow)), "net": str(money(inflow - outflow))}

    # ------------------------------------------------------------------ #
    # Analytics
    # ------------------------------------------------------------------ #
    def pagerank(self, *, damping: float = 0.85, iterations: int = 40) -> dict[str, float]:
        """Flow-weighted PageRank: who accumulates value structurally."""
        n = max(1, len(self.nodes))
        rank = dict.fromkeys(self.nodes, 1.0 / n)
        for _ in range(iterations):
            new = dict.fromkeys(self.nodes, (1 - damping) / n)
            dangling = 0.0
            for node in self.nodes:
                out_keys = [k for k in self._out.get(node, []) if self.edges[k].kind == "transfer"]
                if not out_keys:
                    dangling += rank[node]
                    continue
                total_w = sum(self.edges[k].weight for k in out_keys) or 1.0
                for k in out_keys:
                    edge = self.edges[k]
                    new[edge.dst] = new.get(edge.dst, 0.0) + damping * rank[node] * edge.weight / total_w
            spread = damping * dangling / n
            for node in new:
                new[node] += spread
            rank = new
        return rank

    def communities(self, *, iterations: int = 12) -> dict[str, int]:
        """Label propagation on the undirected projection of the graph."""
        labels = {node: i for i, node in enumerate(sorted(self.nodes))}
        adj: dict[str, Counter[int]] = defaultdict(Counter)
        for edge in self.edges.values():
            if edge.kind in ("ownership", "location"):
                continue
            adj[edge.src][labels[edge.dst]] += 1
            adj[edge.dst][labels[edge.src]] += 1
        for _ in range(iterations):
            changed = False
            for node in sorted(self.nodes):
                if not adj[node]:
                    continue
                best_label, _best_weight = max(
                    adj[node].items(), key=lambda kv: (kv[1], -kv[0])
                )
                if labels[node] != best_label:
                    labels[node] = best_label
                    changed = True
            for edge in self.edges.values():
                if edge.kind in ("ownership", "location"):
                    continue
                adj[edge.src][labels[edge.dst]] += 1
                adj[edge.dst][labels[edge.src]] += 1
            if not changed:
                break
        # Normalise labels to dense integers.
        remap = {label: i for i, label in enumerate(sorted(set(labels.values())))}
        return {node: remap[label] for node, label in labels.items()}

    def shortest_path(self, src: str, dst: str, *, max_depth: int = 8) -> list[str] | None:
        if src not in self.nodes or dst not in self.nodes:
            return None
        queue: deque[list[str]] = deque([[src]])
        seen = {src}
        while queue:
            path = queue.popleft()
            node = path[-1]
            if node == dst:
                return path
            if len(path) >= max_depth:
                continue
            for nxt in self.neighbours(node):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append([*path, nxt])
        return None

    def cycles(self, *, max_len: int = 5) -> list[list[str]]:
        edges = [(e.src, e.dst) for e in self.edges.values() if e.kind == "transfer"]
        return find_cycles(edges, max_len)

    def betweenness_sample(self, *, top: int = 10, max_pairs: int = 400) -> dict[str, float]:
        """Sampled betweenness — full Brandes is unnecessary at case scale and this keeps
        the tool responsive on 100k-node graphs."""
        nodes = sorted(self.nodes)
        if len(nodes) < 3:
            return {}
        scores: dict[str, float] = defaultdict(float)
        pairs = 0
        step = max(1, len(nodes) // 20)
        for i in range(0, len(nodes), step):
            for j in range(i + step, min(len(nodes), i + step * 6), step):
                if pairs >= max_pairs:
                    break
                path = self.shortest_path(nodes[i], nodes[j])
                pairs += 1
                if path and len(path) > 2:
                    for mid in path[1:-1]:
                        scores[mid] += 1.0
        return dict(sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:top])

    def clusters(self, *, min_size: int = 3) -> list[dict[str, Any]]:
        labels = self.communities()
        grouped: dict[int, list[str]] = defaultdict(list)
        for node, label in labels.items():
            grouped[label].append(node)
        out = []
        for label, members in grouped.items():
            if len(members) < min_size:
                continue
            flows = sum(
                (self.edges[k].amount for e in members for k in self._out.get(e, [])
                 if self.edges[k].dst in members and self.edges[k].kind == "transfer"),
                D("0"),
            )
            kinds = Counter(self.nodes[m].kind for m in members)
            out.append(
                {
                    "cluster_id": label,
                    "size": len(members),
                    "internal_flow": str(money(flows)),
                    "composition": dict(kinds),
                    "members": sorted(members)[:40],
                    "accounts": sorted(m for m in members if self.nodes[m].kind == "account")[:20],
                }
            )
        return sorted(out, key=lambda c: c["size"], reverse=True)

    def ego_network(self, node_id: str, *, depth: int = 2) -> dict[str, Any]:
        if node_id not in self.nodes:
            matches = [n for n in self.nodes if node_id.lower() in n.lower()]
            if not matches:
                return {"error": f"Node '{node_id}' not found"}
            node_id = matches[0]
        seen = {node_id}
        frontier = {node_id}
        for _ in range(depth):
            nxt: set[str] = set()
            for node in frontier:
                for n in self.neighbours(node):
                    if n not in seen:
                        seen.add(n)
                        nxt.add(n)
            frontier = nxt
        edges = [e for e in self.edges.values() if e.src in seen and e.dst in seen]
        return {
            "center": node_id,
            "depth": depth,
            "nodes": [
                {"id": n, "label": self.nodes[n].label, "kind": self.nodes[n].kind,
                 "degree": self.degree(n)["total"], "flow": self.total_flow(n)}
                for n in sorted(seen)
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "kind": e.kind, "count": e.count,
                 "amount": str(money(e.amount))}
                for e in edges
            ],
            "total_flow": self.total_flow(node_id),
        }

    def summary(self, *, top: int = 10) -> dict[str, Any]:
        ranks = self.pagerank()
        components = self.clusters(min_size=2)
        node_kinds = Counter(n.kind for n in self.nodes.values())
        hubs = [
            {
                "node": node,
                "label": self.nodes[node].label,
                "kind": self.nodes[node].kind,
                "pagerank": round(score, 6),
                "degree": self.degree(node)["total"],
                "flow": self.total_flow(node),
            }
            for node, score in sorted(ranks.items(), key=lambda kv: kv[1], reverse=True)[:top]
        ]
        return {
            "nodes": self.node_count,
            "edges": self.edge_count,
            "node_kinds": dict(node_kinds),
            "hubs": hubs,
            "clusters": components[:5],
            "cycles": self.cycles(max_len=4)[:5],
            "top_brokers": self.betweenness_sample(top=5),
        }

    # ------------------------------------------------------------------ #
    # Export
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n.node_id, "label": n.label, "kind": n.kind, "attrs": n.attrs}
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "src": e.src, "dst": e.dst, "kind": e.kind, "count": e.count,
                    "amount": str(money(e.amount)), "txn_ids": e.txn_ids,
                }
                for e in self.edges.values()
            ],
        }

    def to_dot(self) -> str:
        colors = {"account": "#1f77b4", "customer": "#2ca02c", "country": "#ff7f0e",
                  "device": "#9467bd", "ip": "#8c564b", "entity": "#7f7f7f"}
        lines = ["digraph anjali {", "  rankdir=LR;", '  node [shape=box, style=rounded, fontname="Helvetica"];']
        for node in self.nodes.values():
            colour = colors.get(node.kind, "#999999")
            label = node.label.replace('"', "'")
            lines.append(f'  "{node.node_id}" [label="{label}\\n({node.kind})", color="{colour}"];')
        for edge in self.edges.values():
            style = "dashed" if edge.kind != "transfer" else "solid"
            label = f"{money(edge.amount)}" if edge.kind == "transfer" else edge.kind
            lines.append(
                f'  "{edge.src}" -> "{edge.dst}" [label="{label}", style={style}, '
                f'penwidth={1 + min(4, edge.count / 3):.1f}];'
            )
        lines.append("}")
        return "\n".join(lines)

    def to_mermaid(self, *, max_nodes: int = 60) -> str:
        lines = ["graph LR"]
        nodes = list(self.nodes.values())[:max_nodes]
        keep = {n.node_id for n in nodes}
        for n in nodes:
            shape_open, shape_close = ("[", "]") if n.kind != "country" else ("((", "))")
            lines.append(f'  {slug(n.node_id)}"{shape_open}{n.label}{shape_close}')
        for edge in self.edges.values():
            if edge.src in keep and edge.dst in keep:
                arrow = "-->" if edge.kind == "transfer" else "-.->"
                lines.append(f"  {slug(edge.src)} {arrow} {slug(edge.dst)}")
        return "\n".join(lines)

    def persist(self, db: Database, *, dataset: str = "default") -> dict[str, int]:
        with db.tx() as conn:
            conn.execute("DELETE FROM nodes WHERE dataset=?", (dataset,))
            conn.execute("DELETE FROM edges WHERE dataset=?", (dataset,))
            for node in self.nodes.values():
                conn.execute(
                    "INSERT OR REPLACE INTO nodes(node_id, dataset, label, kind, attrs) VALUES(?,?,?,?,?)",
                    (node.node_id, dataset, node.label, node.kind, json.dumps(node.attrs, default=str)),
                )
            for edge in self.edges.values():
                conn.execute(
                    "INSERT OR REPLACE INTO edges(edge_id, dataset, src, dst, kind, weight, txn_id, ts, amount) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        f"{dataset}:{edge.key()}",
                        dataset,
                        edge.src,
                        edge.dst,
                        edge.kind,
                        edge.weight,
                        edge.txn_ids[0] if edge.txn_ids else None,
                        edge.last_ts,
                        str(money(edge.amount)),
                    ),
                )
        return {"nodes": self.node_count, "edges": self.edge_count}


def resolve_node_id(graph: EntityGraph, query: str) -> str | None:
    """Accept ``ACC-1001``, ``acct:ACC-1001``, a customer name or a node label."""
    if query in graph.nodes:
        return query
    lowered = query.strip().lower()
    for prefix in ("acct", "cust", "name", "country", "dev", "ip"):
        candidate = f"{prefix}:{query.strip()}"
        if candidate in graph.nodes:
            return candidate
    for node_id, node in graph.nodes.items():
        if lowered in node.label.lower():
            return node_id
    return None


def link_analysis(graph: EntityGraph, subject_a: str, subject_b: str | None = None) -> dict[str, Any]:
    a = resolve_node_id(graph, subject_a)
    if not a:
        return {"error": f"Subject '{subject_a}' not found in the graph."}
    result: dict[str, Any] = {"subject": a, "profile": graph.ego_network(a, depth=1)}
    if subject_b:
        b = resolve_node_id(graph, subject_b)
        if not b:
            return {**result, "error": f"Subject '{subject_b}' not found in the graph."}
        path = graph.shortest_path(a, b)
        result["connection"] = {
            "target": b,
            "path": path,
            "hops": (len(path) - 1) if path else None,
            "narrative": _path_narrative(graph, path) if path else "No path found within 8 hops.",
        }
    return result


def _path_narrative(graph: EntityGraph, path: Sequence[str]) -> str:
    parts = [graph.nodes[n].label for n in path]
    return " → ".join(parts)
