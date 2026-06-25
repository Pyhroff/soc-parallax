"""Graph exploration queries — the interview demos."""
from __future__ import annotations

from app.db import neo4j


def blast_radius(entity_name: str) -> list[dict]:
    """Hosts an entity touched and the external IPs those hosts contacted."""
    return neo4j.run(
        """
        MATCH (u:User {name:$name})-[:LOGGED_INTO]->(h:Host)
        OPTIONAL MATCH (h)-[:RAN]->(:Process)-[:CONNECTED_TO]->(ip:IP)
        RETURN h.name AS host, collect(DISTINCT ip.addr) AS external_ips
        """,
        {"name": entity_name},
    )


def similar_incidents(incident_id: str, min_shared: int = 2) -> list[dict]:
    """Incidents sharing >= min_shared MITRE techniques (campaign clustering)."""
    return neo4j.run(
        """
        MATCH (a:Incident {id:$id})-[:USED_TECHNIQUE]->(t:Technique)<-[:USED_TECHNIQUE]-(b:Incident)
        WHERE a <> b
        WITH b, count(DISTINCT t) AS shared, collect(DISTINCT t.id) AS techniques
        WHERE shared >= $min
        RETURN b.id AS incident, shared, techniques
        ORDER BY shared DESC
        """,
        {"id": incident_id, "min": min_shared},
    )


def likely_next_techniques(technique_id: str, limit: int = 5) -> list[dict]:
    """Threat-evolution seed: techniques that historically followed this one."""
    return neo4j.run(
        """
        MATCH (t:Technique {id:$tid})-[r:PRECEDES]->(next:Technique)
        RETURN next.id AS technique_id, next.name AS name, r.count AS observed
        ORDER BY r.count DESC LIMIT $limit
        """,
        {"tid": technique_id, "limit": limit},
    )


def subgraph_for_incident(incident_id: str) -> dict:
    """Nodes + edges for the Cytoscape view of one incident."""
    rows = neo4j.run(
        """
        MATCH (inc:Incident {id:$id})-[:INVOLVES]->(e)
        OPTIONAL MATCH path = (e)-[*1..2]-(n)
        WITH inc, e, path
        UNWIND (CASE WHEN path IS NULL THEN [e] ELSE nodes(path) END) AS node
        WITH inc, collect(DISTINCT node) AS nodes
        RETURN [x IN nodes | {id: coalesce(x.name, x.addr, x.id),
                              label: head(labels(x))}] AS nodes
        """,
        {"id": incident_id},
    )
    return rows[0] if rows else {"nodes": []}
