"""Write entities and relationships into the Neo4j memory graph.

Idempotent MERGEs so re-ingesting the same telemetry doesn't duplicate nodes.
"""
from __future__ import annotations

from app.db import neo4j
from app.schemas.detection import Detection
from app.schemas.event import UnifiedEvent


def _pkey(host: str | None, name: str) -> str:
    """Process nodes are per host: 'powershell.exe' on two machines is two nodes,
    otherwise every host would appear connected through shared process names."""
    return f"{(host or '?').lower()}|{name.lower()}"


def write_event(ev: UnifiedEvent) -> None:
    if ev.user and ev.host:
        neo4j.run(
            """MERGE (u:User {name:$user})
               MERGE (h:Host {name:$host})
               MERGE (u)-[:LOGGED_INTO]->(h)""",
            {"user": ev.user, "host": ev.host},
        )
    if ev.host and ev.process.name:
        neo4j.run(
            """MERGE (h:Host {name:$host})
               MERGE (p:Process {key:$key}) SET p.name=$proc, p.host=$host
               MERGE (h)-[:RAN]->(p)""",
            {"host": ev.host, "proc": ev.process.name.lower(), "key": _pkey(ev.host, ev.process.name)},
        )
    if ev.process.parent and ev.process.name:
        neo4j.run(
            """MERGE (pp:Process {key:$pkey}) SET pp.name=$parent, pp.host=$host
               MERGE (p:Process {key:$key}) SET p.name=$proc, p.host=$host
               MERGE (pp)-[:SPAWNED]->(p)""",
            {"parent": ev.process.parent.lower(), "proc": ev.process.name.lower(), "host": ev.host or "?",
             "pkey": _pkey(ev.host, ev.process.parent), "key": _pkey(ev.host, ev.process.name)},
        )
    if ev.process.name and ev.network.dest_ip:
        neo4j.run(
            """MERGE (p:Process {key:$key}) SET p.name=$proc, p.host=$host
               MERGE (i:IP {addr:$ip})
               MERGE (p)-[:CONNECTED_TO]->(i)""",
            {"proc": ev.process.name.lower(), "ip": ev.network.dest_ip, "host": ev.host or "?",
             "key": _pkey(ev.host, ev.process.name)},
        )
    if ev.network.dest_ip and ev.network.domain:
        neo4j.run(
            """MERGE (i:IP {addr:$ip})
               MERGE (d:Domain {name:$domain})
               MERGE (i)-[:RESOLVES_TO]->(d)""",
            {"ip": ev.network.dest_ip, "domain": ev.network.domain.lower()},
        )
    if ev.process.name and ev.process.hashes.get("sha256"):
        neo4j.run(
            """MERGE (p:Process {key:$key}) SET p.name=$proc, p.host=$host
               MERGE (f:FileHash {sha256:$sha})
               MERGE (p)-[:HAS_HASH]->(f)""",
            {"proc": ev.process.name.lower(), "sha": ev.process.hashes["sha256"], "host": ev.host or "?",
             "key": _pkey(ev.host, ev.process.name)},
        )


def write_incident(incident_id: str, severity: str, det: Detection,
                   technique_order: list[str]) -> None:
    neo4j.run(
        """MERGE (inc:Incident {id:$id})
           SET inc.severity=$sev, inc.created_at=datetime()""",
        {"id": incident_id, "sev": severity},
    )
    # link incident to its primary entity
    label = {"user": "User", "host": "Host"}.get(det.entity_type)
    if label:
        key = "name"
        neo4j.run(
            f"""MERGE (e:{label} {{{key}:$eid}})
                WITH e MATCH (inc:Incident {{id:$id}})
                MERGE (inc)-[:INVOLVES]->(e)""",
            {"eid": det.entity_id, "id": incident_id},
        )
    # link techniques and build PRECEDES chain
    for ref in det.mitre:
        neo4j.run(
            """MERGE (t:Technique {id:$tid})
               SET t.name=$name, t.tactic=$tactic
               WITH t MATCH (inc:Incident {id:$id})
               MERGE (inc)-[:USED_TECHNIQUE]->(t)""",
            {"tid": ref.technique_id, "name": ref.name, "tactic": ref.tactic, "id": incident_id},
        )
    for a, b in zip(technique_order, technique_order[1:]):
        neo4j.run(
            """MATCH (x:Technique {id:$a}), (y:Technique {id:$b})
               MERGE (x)-[r:PRECEDES]->(y)
               ON CREATE SET r.count=1
               ON MATCH SET r.count=r.count+1""",
            {"a": a, "b": b},
        )
