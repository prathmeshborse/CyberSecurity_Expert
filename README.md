# ◈ Intelligent Cyber Security Knowledge System (CyberSec-KG)

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-green.svg)](https://flask.palletsprojects.com/)
[![RDFLib](https://img.shields.io/badge/Ontology-RDFLib-red.svg)](https://rdflib.readthedocs.io/)

CyberSec-KG is an **Ontology-Driven Intelligent Agent** designed to model, detect, and mitigate cyber security threats. Using Semantic Web technologies (OWL, RDF, SPARQL) and classical AI algorithms, the system functions as a goal-based agent capable of automated reasoning, heuristic search, and constraint-based planning.

## 🚀 Project Motivation
This project translates the framework of an **Intelligent Museum Knowledge System** into the domain of **Cyber Security**. By representing threats as "artefacts" and attack categories as "dynasties," it demonstrates how symbolic AI can organize vast amounts of unstructured security data into a meaningful, searchable, and actionable knowledge graph.

---

## 🧠 AI Implementation Modules

### Module 1: Intelligent Agent Design (PEAS)
The system is implemented as a **Goal-Based Agent**:
- **Performance:** Detection accuracy, reduction of false positives, and heuristic search efficiency.
- **Environment:** Partially observable, deterministic, sequential, and discrete.
- **Actuators:** Classification responses, mitigation suggestions, and CSP security plans.
- **Sensors:** IP addresses, login attempt counts, URL strings, and payload flags.

### Module 2: Knowledge Representation (Ontology & RDF)
- **OWL Ontology:** A custom schema defining the hierarchy of `Threats`, `Vulnerabilities`, and `Mitigations`.
- **Property Chain Reasoning:** Implements the rule: `hasIndicator ∘ indicatesThreat → classifiedAsThreat`.
- **Instance Store:** Over 40 real-world threat individuals (e.g., WannaCry, Log4Shell) stored in **Turtle (.ttl)** format.

### Module 3: Search Algorithms (BFS, DFS, A*)
- **BFS:** Identifies the full scope of an attack originating from a specific source IP.
- **DFS:** Uncovers multi-stage "Attack Chains" through connected nodes.
- **A* Search:** A recommendation engine using a **Heuristic $h(n)$** based on attribute dissimilarity (Type, Vulnerability, and Subnet proximity).

### Module 4 & 6: Expert System & Uncertainty Handling
- **Forward Chaining:** A production rule system that analyzes incoming indicators to infer threat types.
- **Backward Chaining:** Allows the agent to determine what evidence is missing to confirm a specific security goal.
- **MYCIN Certainty Factors:** Handles attribution uncertainty by combining evidence using the MYCIN mathematical model.

### Module 5: Constraint Satisfaction Problem (CSP)
- **Security Planner:** Generates an optimal 5-measure security strategy.
- **Constraints:** Ensures "Type Diversity" (Preventive vs. Detective) and eliminates redundant measures.
- **Backtracking Solver:** Utilizes the **MRV (Minimum Remaining Values)** heuristic for efficient pruning.

---

## 🛠 Tech Stack
- **Backend:** Python 3.12, Flask
- **Reasoning Engine:** RDFLib (SPARQL 1.1)
- **Frontend:** Jinja2, D3.js (Graph Visualization)
- **Data Format:** W3C Turtle (.ttl)

---

## 📂 Project Structure
```text
/cybersec_kg
│
├── app.py                     # Flask Orchestrator & API Routes
├── requirements.txt           # Project Dependencies
│
├── ontology/
│   └── cybersec.ttl           # The Knowledge Base (Turtle RDF)
│
├── modules/
│   ├── knowledge_graph.py     # RDF Loader & SPARQL Manager
│   ├── search_algorithms.py   # BFS, DFS, A* Implementations
│   └── expert_system.py       # MYCIN Logic, Forward Chaining, CSP
│
├── templates/                 # UI Layer (Jinja2)
│   ├── index.html             # Agent PEAS & Mapping
│   ├── analyzer.html          # Expert System Analysis
│   ├── recommendations.html   # A* Recommender
│   ├── graph.html             # D3.js Knowledge Graph
│   └── csp.html               # Security Planner
│
└── static/css/style.css       # Custom Cyber-Grid UI

⚙️ Installation & Setup

1.  Clone the repository:

    git clone https://github.com/yourusername/cybersec_kg.git
    cd cybersec_kg

2.  Set up a virtual environment:

    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate

3.  Install dependencies:

    pip install -r requirements.txt

4.  Run the application:

    python app.py

5.  Access the Dashboard: Open http://127.0.0.1:5001 in your browser.

📊 Domain Mapping Summary (Academic Alignment)

| Museum Project Concept | Cyber Security Equivalent                   |
| :--------------------- | :------------------------------------------ |
| **Artefact**           | Cyber Threat Instance (e.g., WannaCry)      |
| **Dynasty**            | Attack Category (e.g., Ransomware)          |
| **Region**             | Source IP / Network Subnet                  |
| **Deity**              | Target Vulnerability (e.g., CVE-2021-44228) |
| **Material**           | Attack Method (Payload, URL, Script)        |
| **Museum**             | Target System (Web Server, Database)        |

Author: Prathamesh Borse, Nirantar Mandogade
Project: Symbolic AI Minor Project v1.0

