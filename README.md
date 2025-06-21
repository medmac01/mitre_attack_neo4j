# MITRE ATT&CK Neo4j Ingestion Tool

A Python script to ingest MITRE ATT&CK framework data in STIX format into a Neo4j graph database. This tool parses the MITRE ATT&CK STIX bundle and creates a comprehensive graph representation of techniques, tactics, groups, tools, mitigations, and their relationships.


## Graph Schema

The tool creates the following node types:
- **:Technique** - Attack patterns (MITRE techniques and sub-techniques)
- **:Tactic** - Kill chain phases
- **:Group** - Threat actor groups
- **:Tool** - Software used by attackers
- **:Mitigation** - Defensive measures
- **:Campaign** - Named attack campaigns

And these relationship types:
- **USES** - Groups/Tools/Campaigns use Techniques
- **MITIGATES** - Mitigations counter Techniques
- **SUBTECHNIQUE_OF** - Sub-techniques relate to parent techniques
- **REQUIRES_TACTIC** - Techniques belong to Tactics
- **ATTRIBUTED_TO** - Campaigns attributed to Groups

## Prerequisites

- Python 3.7+
- Neo4j Database (local or remote)
- MITRE ATT&CK STIX data file

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/mitre_attack_neo4j.git
cd mitre_attack_neo4j
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Download MITRE ATT&CK data:
```bash
# Create directory for MITRE data
mkdir enterprise-attack

# Download the latest MITRE ATT&CK Enterprise dataset
curl -o enterprise-attack/enterprise-attack.json https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

## Configuration

Create a `.env` file in the project root with your configuration:

```env
# Path to MITRE ATT&CK STIX JSON file
STIX_FILE=enterprise-attack/enterprise-attack.json

# Neo4j connection details
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password_here
```

### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `STIX_FILE` | `enterprise-attack/enterprise-attack.json` | Path to MITRE ATT&CK STIX bundle |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `your_password_here` | Neo4j password |

## Usage

1. Ensure Neo4j is running and accessible
2. Run the ingestion script:

```bash
python main.py
```

The script will:
1. Create uniqueness constraints in Neo4j
2. Parse the MITRE ATT&CK STIX bundle
3. Create nodes for all entities (techniques, groups, tools, etc.)
4. Create relationships between entities
5. Display progress bars during processing

## Example Queries

After ingestion, you can run Cypher queries like:

```cypher
// Find all techniques used by APT1
MATCH (g:Group {name: "APT1"})-[:USES]->(t:Technique)
RETURN g.name, t.name, t.mitre_id

// Find mitigations for a specific technique
MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique {mitre_id: "T1059"})
RETURN m.name, m.mitre_id, t.name

// Find sub-techniques of Command and Scripting Interpreter
MATCH (child:Technique)-[:SUBTECHNIQUE_OF]->(parent:Technique {mitre_id: "T1059"})
RETURN parent.name, child.name, child.mitre_id

// Find all techniques in the Initial Access tactic
MATCH (t:Technique)-[:REQUIRES_TACTIC]->(ta:Tactic {shortname: "initial-access"})
RETURN t.name, t.mitre_id
```

## Data Sources

This tool is designed to work with the official MITRE ATT&CK datasets:
- [MITRE CTI Repository](https://github.com/mitre/cti)
- [Enterprise ATT&CK](https://attack.mitre.org/matrices/enterprise/)

## Dependencies

- `stix2` - STIX 2.0 data parsing
- `neo4j` - Neo4j database driver
- `python-dotenv` - Environment variable loading
- `tqdm` - Progress bar display

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

**Memory Issues with Large Datasets**
- Consider increasing Neo4j heap size
- Process data in smaller batches if needed

## Acknowledgments

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE Corporation](https://www.mitre.org/)
- [STIX 2.0 Specification](https://oasis-open.github.io/cti-documentation/)
