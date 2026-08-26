"""Write entities and relationships into the Neo4j memory graph.

Idempotent MERGEs so re-ingesting the same telemetry doesn't duplicate nodes.
"""
from __future__ import annotations

from app.db import neo4j
from app.schemas.detection import Detection
from app.schemas.event import UnifiedEvent


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
               MERGE (p:Process {name:$proc})
               MERGE (h)-[:RAN]->(p)""",
            {"host": ev.host, "proc": ev.process.name.lower()},
        )
    if ev.process.parent and ev.process.name:
        neo4j.run(
            """MERGE (pp:Process {name:$parent})
               MERGE (p:Process {name:$proc})
               MERGE (pp)-[:SPAWNED]->(p)""",
            {"parent": ev.process.parent.lower(), "proc": ev.process.name.lower()},
        )
    if ev.process.name and ev.network.dest_ip:
        neo4j.run(
            """MERGE (p:Process {name:$proc})
               MERGE (i:IP {addr:$ip})
               MERGE (p)-[:CONNECTED_TO]->(i)""",
            {"proc": ev.process.name.lower(), "ip": ev.network.dest_ip},
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
            """MERGE (p:Process {name:$proc})
               MERGE (f:FileHash {sha256:$sha})
               MERGE (p)-[:HAS_HASH]->(f)""",
            {"proc": ev.process.name.lower(), "sha": ev.process.hashes["sha256"]},
        )


def write_incident(incident_id: str, severity: str, det: Detection,
                   technique_order: list[str]) -> None:
    neo4j.run(
        """MERGE (inc:Incident {id:$id})
           SET inc.severity=$sev, inc.created_at=datetime()""",
        {"id": incident_id, "sev": severity},
    )
    # link incident to its primary entity
    label = {"user": "User", "host": "Host", "process": "Process"}.get(det.entity_type)
    if label:
        key = {"User": "name", "Host": "name", "Process": "name"}[label]
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
