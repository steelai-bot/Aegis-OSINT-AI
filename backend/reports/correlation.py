"""Finding correlation graph generation for passive report data."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


ENTITY_KEYS = ("value", "target", "domain", "email", "url", "ip", "host", "hostname")


def _read_value(item: Any, key: str, default: Any = "") -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _node(node_id: str, label: str, node_type: str) -> dict[str, str]:
    return {"id": node_id, "label": label, "type": node_type}


def _edge(source: str, target: str, relationship: str) -> dict[str, str]:
    return {"source": source, "target": target, "relationship": relationship}


def _finding_data(finding: Any) -> Mapping[str, Any]:
    data = _read_value(finding, "data", {}) or {}
    return data if isinstance(data, Mapping) else {}


def _finding_title(finding: Any, index: int) -> str:
    data = _finding_data(finding)
    return str(data.get("title") or data.get("summary") or _read_value(finding, "source", f"Finding {index + 1}"))


def _entity_values(finding: Any) -> list[str]:
    data = _finding_data(finding)
    values: list[str] = []
    for key in ENTITY_KEYS:
        top_level = finding.get(key) if isinstance(finding, Mapping) else getattr(finding, "__dict__", {}).get(key)
        for candidate in (top_level, data.get(key)):
            if isinstance(candidate, str) and candidate.strip():
                values.append(candidate.strip())
    return sorted(set(values))


def build_finding_correlation_graph(findings: Sequence[Any]) -> dict[str, Any]:
    """Build a deterministic graph from persisted finding records."""

    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def add_node(node: dict[str, str]) -> None:
        nodes[node["id"]] = node

    def add_edge(source: str, target: str, relationship: str) -> None:
        key = (source, target, relationship)
        if key not in seen_edges:
            edges.append(_edge(source, target, relationship))
            seen_edges.add(key)

    for index, finding in enumerate(findings):
        finding_id = f"finding:{index + 1}"
        source = str(_read_value(finding, "source", "unknown") or "unknown")
        severity = str(_read_value(finding, "severity", "info") or "info").lower()
        finding_type = str(_read_value(finding, "type", "") or _finding_data(finding).get("type") or "finding")

        add_node(_node(finding_id, _finding_title(finding, index), "finding"))
        source_id = f"source:{source}"
        severity_id = f"severity:{severity}"
        type_id = f"type:{finding_type}"
        add_node(_node(source_id, source, "source"))
        add_node(_node(severity_id, severity, "severity"))
        add_node(_node(type_id, finding_type, "finding_type"))
        add_edge(finding_id, source_id, "reported_by")
        add_edge(finding_id, severity_id, "has_severity")
        add_edge(finding_id, type_id, "has_type")

        for value in _entity_values(finding):
            entity_id = f"entity:{value.lower()}"
            add_node(_node(entity_id, value, "entity"))
            add_edge(finding_id, entity_id, "mentions")

    ordered_nodes = sorted(nodes.values(), key=lambda node: (node["type"], node["id"]))
    ordered_edges = sorted(edges, key=lambda edge: (edge["source"], edge["relationship"], edge["target"]))
    return {
        "nodes": ordered_nodes,
        "edges": ordered_edges,
        "summary": {
            "node_count": len(ordered_nodes),
            "edge_count": len(ordered_edges),
            "finding_count": len(findings),
        },
    }
