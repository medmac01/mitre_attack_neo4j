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

def extract_mitre_id(stix_obj):
    """
    Look through stix_obj["external_references"] and return the first external_id
    where source_name == "mitre-attack". If none found, returns "".
    """
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


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
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (c:Campaign) REQUIRE c.stix_id IS UNIQUE;")
    session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (mal:Malware) REQUIRE mal.stix_id IS UNIQUE;")


def merge_technique(tx, obj):
    """
    STIX 'attack-pattern' → Neo4j :Technique
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")
    platforms   = obj.get("x_mitre_platforms", [])

    # Extract MITRE ID from external_references (e.g. "T1059", "T1059.001")
    mitre_id = extract_mitre_id(obj)

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

    # Link Technique → Tactic based on kill_chain_phases
    for phase in obj.get("kill_chain_phases", []):
        tactic_short = phase.get("phase_name", "")
        if tactic_short:
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
    STIX 'intrusion-set' → Neo4j :Group
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")
    aliases     = obj.get("aliases", [])

    # Extract MITRE Group ID if present
    mitre_id = extract_mitre_id(obj)

    tx.run(
        """
        MERGE (g:Group {stix_id: $stix_id})
        ON CREATE SET g.mitre_id    = $mitre_id,
                      g.name        = $name,
                      g.description = $description,
                      g.aliases     = $aliases
        ON MATCH SET  g.name        = $name,
                      g.description = $description,
                      g.aliases     = $aliases
        """,
        stix_id=stix_id,
        mitre_id=mitre_id,
        name=name,
        description=description,
        aliases=aliases
    )

def merge_tool(tx, obj):
    """
    STIX 'tool' → Neo4j :Tool
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")
    aliases     = obj.get("aliases", [])

    # Extract MITRE Tool ID if present
    mitre_id = extract_mitre_id(obj)

    tx.run(
        """
        MERGE (to:Tool {stix_id: $stix_id})
        ON CREATE SET to.mitre_id    = $mitre_id,
                      to.name        = $name,
                      to.description = $description,
                      to.aliases     = $aliases
        ON MATCH SET  to.name        = $name,
                      to.description = $description,
                      to.aliases     = $aliases
        """,
        stix_id=stix_id,
        mitre_id=mitre_id,
        name=name,
        description=description,
        aliases=aliases
    )

def merge_mitigation(tx, obj):
    """
    STIX 'course-of-action' → Neo4j :Mitigation
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")

    # Extract MITRE Mitigation ID if present
    mitre_id = extract_mitre_id(obj)

    tx.run(
        """
        MERGE (m:Mitigation {stix_id: $stix_id})
        ON CREATE SET m.mitre_id    = $mitre_id,
                      m.name        = $name,
                      m.description = $description
        ON MATCH SET  m.name        = $name,
                      m.description = $description
        """,
        stix_id=stix_id,
        mitre_id=mitre_id,
        name=name,
        description=description
    )

def merge_tactic(tx, obj):
    """
    STIX 'x-mitre-tactic' → Neo4j :Tactic
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    shortname   = obj.get("x_mitre_shortname", "")
    description = obj.get("description", "")

    # Tactics generally do not have an external_id the same way techniques do,
    # but if they do (rarely), extract it. Otherwise leave blank.
    mitre_id = extract_mitre_id(obj)

    tx.run(
        """
        MERGE (ta:Tactic {stix_id: $stix_id})
        ON CREATE SET ta.mitre_id    = $mitre_id,
                      ta.name        = $name,
                      ta.shortname   = $shortname,
                      ta.description = $description
        ON MATCH SET  ta.name        = $name,
                      ta.shortname   = $shortname,
                      ta.description = $description
        """,
        stix_id=stix_id,
        mitre_id=mitre_id,
        name=name,
        shortname=shortname,
        description=description
    )

def merge_campaign(tx, obj):
    """
    STIX 'campaign' → Neo4j :Campaign
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")
    aliases     = obj.get("aliases", [])

    # Extract MITRE Campaign ID if present
    mitre_id = extract_mitre_id(obj)

    tx.run(
        """
        MERGE (c:Campaign {stix_id: $stix_id})
        ON CREATE SET c.mitre_id    = $mitre_id,
                      c.name        = $name,
                      c.description = $description,
                      c.aliases     = $aliases
        ON MATCH SET  c.name        = $name,
                      c.description = $description,
                      c.aliases     = $aliases
        """,
        stix_id=stix_id,
        mitre_id=mitre_id,
        name=name,
        description=description,
        aliases=aliases
    )

def merge_malware(tx, obj):
    """
    STIX 'malware' → Neo4j :Malware
    """
    stix_id     = obj["id"]
    name        = obj.get("name", "")
    description = obj.get("description", "")
    aliases     = obj.get("aliases", [])

    # Extract MITRE Malware ID if present
    mitre_id = extract_mitre_id(obj)

    tx.run(
        """
        MERGE (m:Malware {stix_id: $stix_id})
        ON CREATE SET m.mitre_id    = $mitre_id,
                      m.name        = $name,
                      m.description = $description,
                      m.aliases     = $aliases
        ON MATCH SET  m.name        = $name,
                      m.description = $description,
                      m.aliases     = $aliases
        """,
        stix_id=stix_id,
        mitre_id=mitre_id,
        name=name,
        description=description,
        aliases=aliases
    )

def merge_stix_relationship(tx, rel):
    """
    Create/merge a relationship edge between two STIX objects. 
    Handles: "uses", "mitigates", "subtechnique-of", "attributed-to" (campaign→group), etc.
    """
    rel_type = rel.get("relationship_type")
    src_ref  = rel.get("source_ref")
    tgt_ref  = rel.get("target_ref")

    # 1) Group or Tool "uses" Technique
    if rel_type == "uses":
        if src_ref.startswith("intrusion-set--"):
            tx.run(
                """
                MATCH (g:Group {stix_id: $src_ref})
                MATCH (t:Technique {stix_id: $tgt_ref})
                MERGE (g)-[:USES]->(t)
                """,
                src_ref=src_ref, tgt_ref=tgt_ref
            )
            tx.run(
                """
                MATCH (g:Group {stix_id: $src_ref})
                MATCH (t:Tool {stix_id: $tgt_ref})
                MERGE (g)-[:USES]->(t)
                """,
                src_ref=src_ref, tgt_ref=tgt_ref
            )
            tx.run(
                """
                MATCH (g:Group {stix_id: $src_ref})
                MATCH (m:Malware {stix_id: $tgt_ref})
                MERGE (g)-[:USES]->(m)
                """,
                src_ref=src_ref, tgt_ref=tgt_ref
            )
        elif src_ref.startswith("tool--"):
            tx.run(
                """
                MATCH (to:Tool {stix_id: $src_ref})
                MATCH (t:Technique {stix_id: $tgt_ref})
                MERGE (to)-[:USES]->(t)
                """,
                src_ref=src_ref, tgt_ref=tgt_ref
            )
        elif src_ref.startswith("campaign--"):
            tx.run(
                """
                MATCH (c:Campaign {stix_id: $src_ref})
                MATCH (t:Technique {stix_id: $tgt_ref})
                MERGE (c)-[:USES]->(t)
                """,
                src_ref=src_ref, tgt_ref=tgt_ref
            )
        elif src_ref.startswith("malware--"):
            tx.run(
                """
                MATCH (m:Malware {stix_id: $src_ref})
                MATCH (t:Technique {stix_id: $tgt_ref})
                MERGE (m)-[:USES]->(t)
                """,
                src_ref=src_ref, tgt_ref=tgt_ref
            )

    # 2) Mitigation → Technique
    elif rel_type == "mitigates":
        tx.run(
            """
            MATCH (m:Mitigation {stix_id: $src_ref})
            MATCH (t:Technique  {stix_id: $tgt_ref})
            MERGE (m)-[:MITIGATES]->(t)
            """,
            src_ref=src_ref, tgt_ref=tgt_ref
        )

    # 3) Sub-technique → Parent technique
    elif rel_type == "subtechnique-of":
        tx.run(
            """
            MATCH (child:Technique {stix_id: $src_ref})
            MATCH (parent:Technique {stix_id: $tgt_ref})
            MERGE (child)-[:SUBTECHNIQUE_OF]->(parent)
            """,
            src_ref=src_ref, tgt_ref=tgt_ref
        )

    # 4) Campaign “attributed-to” Group  (Campaign → Group)
    elif rel_type == "attributed-to":
        tx.run(
            """
            MATCH (c:Campaign {stix_id: $src_ref})
            MATCH (g:Group    {stix_id: $tgt_ref})
            MERGE (c)-[:ATTRIBUTED_TO]->(g)
            """,
            src_ref=src_ref, tgt_ref=tgt_ref
        )

    # 5) Optional: Campaign “uses” Technique (sometimes campaigns directly use techniques)
    elif rel_type == "uses" and src_ref.startswith("campaign--"):
        tx.run(
            """
            MATCH (c:Campaign {stix_id: $src_ref})
            MATCH (t:Technique {stix_id: $tgt_ref})
            MERGE (c)-[:USES]->(t)
            """,
            src_ref=src_ref, tgt_ref=tgt_ref
        )

def load_and_ingest_stix():
    """
    Main function: parse STIX bundle, create nodes + relationships in Neo4j.
    """
    # 1) Read the entire STIX JSON file
    if not os.path.exists(STIX_FILE):
        # Download the STIX file from github if it doesn't exist
        STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        import requests
        response = requests.get(STIX_URL)
        if response.status_code == 200:
            print(f"Downloading STIX file from {STIX_URL}...")
            os.makedirs(os.path.dirname(STIX_FILE), exist_ok=True)
            with open(STIX_FILE, "w", encoding="utf-8") as f:
                f.write(response.text)
        else:
            raise FileNotFoundError(f"STIX file not found at {STIX_FILE}, and could not be downloaded from {STIX_URL}")

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
                       ["attack-pattern", "campaign", "intrusion-set", "tool", "course-of-action", "x-mitre-tactic", "malware"]]
        
        print(f"Creating {len(node_objects)} nodes...")
        for obj in tqdm(node_objects, desc="Creating nodes"):
            obj_type = obj.get("type")

            if obj_type == "attack-pattern":
                # STIX "attack-pattern" → Neo4j :Technique
                session.execute_write(merge_technique, obj)

            elif obj_type == "malware":
                # STIX "malware" → Neo4j :Malware
                session.execute_write(merge_malware, obj)

            elif obj_type == "campaign":
                # STIX "campaign" → Neo4j :Campaign
                session.execute_write(merge_campaign, obj)

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