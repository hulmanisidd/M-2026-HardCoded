"""Push the HardCoded seed graph into Neo4j so you can show it in Neo4j Browser.

Run from the repo root (PowerShell):
    pip install neo4j
    $env:PYTHONPATH = "$PWD"
    $env:NEO4J_URI = "bolt://localhost:7687"
    $env:NEO4J_USER = "neo4j"
    $env:NEO4J_PASSWORD = "<your password>"
    python scripts/load_seed_to_neo4j.py

This is a read-only VIEW of the graph for the demo. It does not replace
InMemoryGraphRepository. It wipes label :Entity nodes first, so re-running is safe.
"""
import json
import os
from collections import defaultdict

from neo4j import GraphDatabase

from backend.graph.seed_data import SEED_NOW, build_seed

seed = build_seed()
by_id = {e.entity_id: e for e in seed.entities}
key_of_edge = {v: k for k, v in seed.edge_ids.items()}  # edge_id -> "E1"..."E13"


def effective_status(edge):
    """Mirror snapshot(): an edge outside its validity window shows as EXPIRED."""
    if edge.valid_until and edge.valid_until <= SEED_NOW:
        return "EXPIRED"
    return str(edge.status.value if hasattr(edge.status, "value") else edge.status).upper()


nodes = [
    {
        "id": e.entity_id,
        "name": e.name,
        "type": str(e.entity_type.value if hasattr(e.entity_type, "value") else e.entity_type),
        "criticality": str(e.criticality.value if hasattr(e.criticality, "value") else e.criticality) if e.criticality else "unknown",
        "account": e.account_id or "",
    }
    for e in seed.entities
]

rels = defaultdict(list)
for ed in seed.edges:
    rtype = str(ed.relation_type.value if hasattr(ed.relation_type, "value") else ed.relation_type).upper()
    rels[rtype].append({
        "src": ed.source_id,
        "dst": ed.target_id,
        "edge_id": ed.edge_id,
        "key": key_of_edge[ed.edge_id],
        "status": effective_status(ed),
        "conditions": json.dumps(ed.conditions) if ed.conditions else "",
        "valid_until": ed.valid_until.isoformat() if ed.valid_until else "",
    })

driver = GraphDatabase.driver(
    os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
    auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]),
)
with driver.session() as s:
    s.run("MATCH (n:Entity) DETACH DELETE n")
    s.run("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE")
    s.run(
        "UNWIND $rows AS r CREATE (n:Entity {id:r.id, name:r.name, type:r.type, "
        "criticality:r.criticality, account:r.account})",
        rows=nodes,
    )
    for rtype, rows in rels.items():
        # relationship type comes from our own enum, not user input
        s.run(
            "UNWIND $rows AS r MATCH (a:Entity {id:r.src}), (b:Entity {id:r.dst}) "
            f"CREATE (a)-[:{rtype} {{edge_id:r.edge_id, key:r.key, status:r.status, "
            "conditions:r.conditions, valid_until:r.valid_until}]->(b)",
            rows=rows,
        )
driver.close()
print(f"Loaded {len(nodes)} nodes and {sum(len(v) for v in rels.values())} edges.")
