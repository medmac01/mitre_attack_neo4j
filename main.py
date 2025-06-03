import json
import os
from stix2 import parse
from neo4j import GraphDatabase
from tqdm import tqdm

from dotenv import load_dotenv
load_dotenv()

# Path to the MITRE ATT&CK STIX bundle JSON file:
STIX_FILE = os.getenv("STIX_FILE", "enterprise-attack/enterprise-attack.json")

# Neo4j connection information:
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "your_password_here")


def create_constraints(session):
    """
    Create uniqueness constraints so we never insert duplicate STIX objects.
    Each STIX object has a unique stix_id (e.g., "attack-pattern--xxxx...").
    """
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (t:Technique) REQUIRE t.stix_id IS UNIQUE;")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (g:Group) REQUIRE g.stix_id IS UNIQUE;")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (to:Tool) REQUIRE to.stix_id IS UNIQUE;")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (m:Mitigation) REQUIRE m.stix_id IS UNIQUE;")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (ta:Tactic) REQUIRE ta.stix_id IS UNIQUE;")

def merge_technique(tx, obj):
    """
    Create or merge a Technique node from a STIX attack-pattern object.
    - obj["id"] is the STIX ID, e.g. "attack-pattern--d9b4...".
    - obj["x_mitre_id"] is the ATT&CK ID, e.g. "T1059".
    - obj["name"], obj["description"], etc. can be stored as properties.
    - obj["x_mitre_platforms"] is a list of platforms.
    - obj["kill_chain_phases"] has a list of which tactics each technique belongs to.
    """
    stix_id      = obj["id"]
    mitre_id     = obj.get("x_mitre_id", "")
    name         = obj.get("name", "")
    description  = obj.get("description", "")
    platforms    = obj.get("x_mitre_platforms", [])

    # Create / Merge the Technique node
    tx.run(
        """
        MERGE (t:Technique {stix_id: $stix_id})
        ON CREATE SET t.mitre_id    = $mitre_id,
                      t.name        = $name,
                      t.description = $description,
                      t.platforms   = $platforms
        ON MATCH SET  t.name        = $name, 
                      t.description = $description,
                      t.platforms   = $platforms
        """,
        stix_id=stix_id,
        mitre_id=mitre_id,
        name=name,
        description=description,
        platforms=platforms
    )

    # If this technique has kill_chain_phases, link to Tactic nodes
    if "kill_chain_phases" in obj:
        for phase in obj["kill_chain_phases"]:
            # e.g. phase["phase_name"] might be "execution"
            tactic_short = phase.get("phase_name", "")
            if tactic_short:
                # Create/Merge the Tactic node, then link:
                tx.run(
                    """
                    MERGE (ta:Tactic {shortname: $shortname})
                    ON CREATE SET ta.name = $phase_name
                    """,
                    shortname=tactic_short,
                    phase_name=phase.get("phase_name", "")
                )
                tx.run(
                    """
                    MATCH (t:Technique {stix_id: $stix_id})
                    MATCH (ta:Tactic {shortname: $shortname})
                    MERGE (t)-[:REQUIRES_TACTIC]->(ta)
                    """,
                    stix_id=stix_id,
                    shortname=tactic_short
                )

def merge_group(tx, obj):
    """
    Create/merge an ATT&CK Group (STIX intrusion-set).
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")
    aliases     = obj.get("aliases", [])

    tx.run(
        """
        MERGE (g:Group {stix_id: $stix_id})
        ON CREATE SET g.name        = $name,
                      g.description = $description,
                      g.aliases     = $aliases
        ON MATCH SET  g.name        = $name,
                      g.description = $description,
                      g.aliases     = $aliases
        """,
        stix_id=stix_id,
        name=name,
        description=description,
        aliases=aliases
    )

def merge_tool(tx, obj):
    """
    Create/merge an ATT&CK Tool (STIX tool).
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")
    aliases     = obj.get("aliases", [])

    tx.run(
        """
        MERGE (to:Tool {stix_id: $stix_id})
        ON CREATE SET to.name        = $name,
                      to.description = $description,
                      to.aliases     = $aliases
        ON MATCH SET  to.name        = $name,
                      to.description = $description,
                      to.aliases     = $aliases
        """,
        stix_id=stix_id,
        name=name,
        description=description,
        aliases=aliases
    )

def merge_mitigation(tx, obj):
    """
    Create/merge a Mitigation (STIX course-of-action).
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")

    tx.run(
        """
        MERGE (m:Mitigation {stix_id: $stix_id})
        ON CREATE SET m.name        = $name,
                      m.description = $description
        ON MATCH SET  m.name        = $name,
                      m.description = $description
        """,
        stix_id=stix_id,
        name=name,
        description=description
    )

def merge_tactic(tx, obj):
    """
    Create/merge a Tactic (STIX x_mitre_tactic).
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    shortname   = obj.get("x_mitre_shortname", "")
    description = obj.get("description", "")

    tx.run(
        """
        MERGE (ta:Tactic {stix_id: $stix_id})
        ON CREATE SET ta.name         = $name,
                      ta.shortname    = $shortname,
                      ta.description  = $description
        ON MATCH SET  ta.name         = $name,
                      ta.shortname    = $shortname,
                      ta.description  = $description
        """,
        stix_id=stix_id,
        name=name,
        shortname=shortname,
        description=description
    )

def merge_stix_relationship(tx, rel):
    """
    Create/merge a relationship edge between two STIX objects.
    In MITRE ATT&CK STIX, a "relationship" object looks like:
      {
        "type": "relationship",
        "id": "relationship--xxxx...",
        "relationship_type": "uses"   (or "mitigates", "subtechnique-of", etc.),
        "source_ref": "intrusion-set--yyyy...",
        "target_ref": "attack-pattern--zzzz...",
        ...
      }
    We read `relationship_type` and create a Neo4j edge accordingly.

    You may need to adjust this mapping depending on which relationships
    you care about. Below is a minimal mapping:
      - "uses"          → (:Group or :Tool)-[:USES]->(:Technique)
      - "mitigates"     → (:Mitigation)-[:MITIGATES]->(:Technique)
      - "revoked-by"    → maybe skip or mark outdated
      - "subtechnique-of" → (:Technique)-[:SUBTECHNIQUE_OF]->(:Technique)
      - "derived-from"  → skip for ATT&CK
      - (others)        → skip or log
    """
    rel_type   = rel.get("relationship_type")
    src_ref    = rel.get("source_ref")
    tgt_ref    = rel.get("target_ref")

    # If it’s “uses”, we create (Group or Tool)-[:USES]->(Technique)
    if rel_type == "uses":
        # We need to see if source is a Group or a Tool
        if src_ref.startswith("intrusion-set--"):
            # Group uses Technique
            tx.run(
                """
                MATCH (g:Group {stix_id: $src_ref})
                MATCH (t:Technique {stix_id: $tgt_ref})
                MERGE (g)-[:USES]->(t)
                """,
                src_ref=src_ref,
                tgt_ref=tgt_ref
            )
        elif src_ref.startswith("tool--"):
            # Tool uses Technique
            tx.run(
                """
                MATCH (to:Tool {stix_id: $src_ref})
                MATCH (t:Technique {stix_id: $tgt_ref})
                MERGE (to)-[:USES]->(t)
                """,
                src_ref=src_ref,
                tgt_ref=tgt_ref
            )

    # If it’s “mitigates”, Course-of-Action (Mitigation) -> Technique
    elif rel_type == "mitigates":
        tx.run(
            """
            MATCH (m:Mitigation {stix_id: $src_ref})
            MATCH (t:Technique  {stix_id: $tgt_ref})
            MERGE (m)-[:MITIGATES]->(t)
            """,
            src_ref=src_ref,
            tgt_ref=tgt_ref
        )

    # If it’s “subtechnique-of”, then create a SUBTECHNIQUE_OF edge
    elif rel_type == "subtechnique-of":
        tx.run(
            """
            MATCH (t_child:Technique {stix_id: $src_ref})
            MATCH (t_parent:Technique {stix_id: $tgt_ref})
            MERGE (t_child)-[:SUBTECHNIQUE_OF]->(t_parent)
            """,
            src_ref=src_ref,
            tgt_ref=tgt_ref
        )

    # You can add more cases here (e.g. “revoked-by” to mark deprecated techniques, etc.)

def load_and_ingest_stix():
    """
    Main function: parse STIX bundle, create nodes + relationships in Neo4j.
    """
    # 1) Read the entire STIX JSON file
    if not os.path.exists(STIX_FILE):
        raise FileNotFoundError(f"STIX file not found at {STIX_FILE}")

    with open(STIX_FILE, "r", encoding="utf-8") as f:
        stix_bundle = json.load(f)

    # 2) Connect to Neo4j
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        # 3) Create uniqueness constraints
        print("Creating constraints...")
        create_constraints(session)

        # 4) Iterate once to create all nodes (Technique, Tactic, Group, Tool, Mitigation)
        objects = stix_bundle.get("objects", [])
        
        # Filter objects for node creation
        node_objects = [obj for obj in objects if obj.get("type") in 
                       ["attack-pattern", "intrusion-set", "tool", "course-of-action", "x-mitre-tactic"]]
        
        print(f"Creating {len(node_objects)} nodes...")
        for obj in tqdm(node_objects, desc="Creating nodes"):
            obj_type = obj.get("type")

            if obj_type == "attack-pattern":
                # STIX "attack-pattern" → Neo4j :Technique
                session.execute_write(merge_technique, obj)

            elif obj_type == "intrusion-set":
                # STIX "intrusion-set" → Neo4j :Group
                session.execute_write(merge_group, obj)

            elif obj_type == "tool":
                # STIX "tool" → Neo4j :Tool
                session.execute_write(merge_tool, obj)

            elif obj_type == "course-of-action":
                # STIX "course-of-action" → Neo4j :Mitigation
                session.execute_write(merge_mitigation, obj)

            elif obj_type == "x-mitre-tactic":
                # STIX "x-mitre-tactic" → Neo4j :Tactic
                session.execute_write(merge_tactic, obj)

        # 5) Iterate a second pass to create relationships from STIX "relationship" objects
        relationship_objects = [obj for obj in objects if obj.get("type") == "relationship"]
        
        print(f"Creating {len(relationship_objects)} relationships...")
        for obj in tqdm(relationship_objects, desc="Creating relationships"):
            session.execute_write(merge_stix_relationship, obj)

    driver.close()
    print("✅ Ingestion complete.")


if __name__ == "__main__":
    load_and_ingest_stix()