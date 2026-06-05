"""Finding correlation graph tests."""

from backend.reports import build_finding_correlation_graph


def test_finding_correlation_graph_links_findings_sources_severity_types_and_entities() -> None:
    findings = [
        {
            "source": "dns",
            "severity": "medium",
            "type": "dns.a",
            "value": "example.com",
            "data": {"title": "DNS A record", "ip": "203.0.113.10"},
        },
        {
            "source": "crtsh",
            "severity": "low",
            "data": {"title": "Certificate match", "domain": "example.com", "type": "certificate.domain"},
        },
    ]

    graph = build_finding_correlation_graph(findings)
    node_ids = {node["id"] for node in graph["nodes"]}
    edge_keys = {(edge["source"], edge["target"], edge["relationship"]) for edge in graph["edges"]}

    assert "finding:1" in node_ids
    assert "finding:2" in node_ids
    assert "source:dns" in node_ids
    assert "source:crtsh" in node_ids
    assert "severity:medium" in node_ids
    assert "entity:example.com" in node_ids
    assert "entity:203.0.113.10" in node_ids
    assert ("finding:1", "source:dns", "reported_by") in edge_keys
    assert ("finding:1", "entity:example.com", "mentions") in edge_keys
    assert ("finding:2", "entity:example.com", "mentions") in edge_keys
    assert graph["summary"]["finding_count"] == 2
    assert graph["summary"]["node_count"] == len(graph["nodes"])
    assert graph["summary"]["edge_count"] == len(graph["edges"])


def test_empty_finding_correlation_graph_is_stable() -> None:
    assert build_finding_correlation_graph([]) == {
        "nodes": [],
        "edges": [],
        "summary": {"node_count": 0, "edge_count": 0, "finding_count": 0},
    }
