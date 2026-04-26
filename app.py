"""
BACKEND: Flask API for Intelligent Cyber Security Knowledge System
Exposes REST endpoints for all AI modules.
Fully synchronized with Ontology-Driven Expert System and Search Engine.
"""

import os
from flask import Flask, render_template, request, jsonify

# Module imports
from modules.knowledge_graph import CyberSecKnowledgeGraph
from modules.search_algorithms import ThreatGraphSearch
from modules.expert_system import KnowledgeBase, CSPSolver

app = Flask(__name__)

# ============================================================
# INITIALIZE KNOWLEDGE GRAPH & SEARCH ENGINE
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Ensure this matches your actual file path
ONTOLOGY_PATH = os.path.join(BASE_DIR, "ontology", "cybersec.ttl")

kg = CyberSecKnowledgeGraph(ontology_path=ONTOLOGY_PATH)
if kg.load_ontology():
    print("✅ Ontology loaded and inference applied.")
else:
    print("❌ Failed to load ontology. Check file path.")

# Build the graph dictionary once for the searcher
graph_dict = kg.build_graph_dict()
searcher = ThreatGraphSearch(graph_dict)

# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def index(): return render_template("index.html")

@app.route("/analyzer")
def analyzer(): return render_template("analyzer.html")

@app.route("/query")
def query_page(): return render_template("query.html")

@app.route("/recommendations")
def recommendations(): return render_template("recommendations.html")

@app.route("/graph")
def graph_page(): return render_template("graph.html")

@app.route("/csp")
def csp_page(): return render_template("csp.html")

# ============================================================
# KNOWLEDGE GRAPH & SPARQL API
# ============================================================

@app.route("/api/stats")
def api_stats():
    return jsonify(kg.get_statistics())

@app.route("/api/threats/all")
def api_all_threats():
    threats = kg.get_all_threats()
    for t in threats:
        uri = t.get('threat', '')
        t['threat_id'] = uri.split('/')[-1] if '/' in uri else uri
        t_type = t.get('type', '')
        t['type_short'] = t_type.split('#')[-1] if '#' in t_type else t_type.split('/')[-1]
    return jsonify(threats)

@app.route("/api/threats/phishing")
def api_phishing(): return jsonify(kg.get_phishing_attacks())

@app.route("/api/threats/malware")
def api_malware(): return jsonify(kg.get_malware_threats())

@app.route("/api/threats/brute-force")
def api_brute_force(): return jsonify(kg.get_brute_force_attacks())

@app.route("/api/threats/high-severity")
def api_high_severity():
    threshold = float(request.args.get("threshold", 8.0))
    return jsonify(kg.get_high_severity_threats(threshold))

@app.route("/api/threats/by-ip")
def api_threats_by_ip():
    ip = request.args.get("ip", "")
    return jsonify(kg.get_threats_by_ip(ip))

@app.route("/api/inference/property-chain")
def api_property_chain():
    return jsonify(kg.get_property_chain_inferences())

@app.route("/api/sparql", methods=["POST"])
def api_sparql():
    data = request.get_json()
    query = data.get("query", "")
    if not query: return jsonify({"error": "Query required"}), 400
    return jsonify({"results": kg.sparql_query(query)})

# ============================================================
# THREAT ANALYZER API (EXPERT SYSTEM)
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()
    ip = data.get("ip", "")
    login_attempts = int(data.get("login_attempts", 0))
    url = data.get("url", "").lower()
    payload = data.get("payload", False)
    email_link = data.get("email_link", False)

    # Heuristic for demo
    is_suspicious_ip = any(ip.startswith(s) for s in ["185.", "45.", "203.", "192."])
    is_malicious_url = any(p in url for p in ["phish", "verify", "secure"]) if url else False

    kb = KnowledgeBase(rdf_graph=kg.graph)
    kb.assert_fact("failed_login_attempts", login_attempts)
    kb.assert_fact("suspicious_ip", is_suspicious_ip)
    kb.assert_fact("url_is_malicious", is_malicious_url)
    kb.assert_fact("email_contains_link", email_link or bool(url))
    kb.assert_fact("suspicious_payload", payload)
    kb.assert_fact("mass_file_encryption", payload)
    kb.assert_fact("sql_keywords_in_input", any(k in url for k in ["select", "union", "drop"]) if url else False)
    kb.assert_fact("unusual_db_queries", bool(url))
    kb.assert_fact("request_rate", login_attempts * 10)
    kb.assert_fact("multiple_source_ips", login_attempts > 100)
    kb.assert_fact("unknown_exploit_signature", payload)
    kb.assert_fact("high_severity_cve", payload)
    kb.assert_fact("targeted_individual", email_link)
    kb.assert_fact("impersonation_detected", email_link)
    kb.assert_fact("ssl_certificate_mismatch", bool(url) and "https" not in url)
    kb.assert_fact("traffic_rerouted", login_attempts > 0)
    kb.assert_fact("suspicious_process", payload)
    kb.assert_fact("antivirus_alert", payload)
    kb.assert_fact("large_data_transfer", login_attempts > 50)
    kb.assert_fact("unusual_destination_ip", bool(ip))

    conclusions, fired_rules = kb.forward_chain()
    
    # Matching Search Engine results
    rdf_threats = kg.get_threats_by_ip(ip) if ip else []
    bfs_results = searcher.bfs_threats_from_ip(ip) if ip else []

    # WRAPPING IN "expert_system" TO MATCH JS
    return jsonify({
        "input": {**data, "is_suspicious_ip": is_suspicious_ip, "is_malicious_url": is_malicious_url},
        "expert_system": {
            "conclusions": conclusions,
            "fired_rules": fired_rules
        },
        "rdf_threats": rdf_threats[:5],
        "bfs_related": bfs_results[:5]
    })


@app.route("/api/backward-chain", methods=["POST"])
def api_backward_chain():
    data = request.get_json()
    kb = KnowledgeBase(rdf_graph=kg.graph)
    for k, v in data.get("facts", {}).items():
        kb.assert_fact(k, v)
    return jsonify(kb.backward_chain(data.get("goal", "")))

# ============================================================
# SEARCH & PLANNING APIS
# ============================================================

@app.route("/api/search/bfs", methods=["POST"])
def api_bfs():
    data = request.get_json()
    return jsonify({"results": searcher.bfs_threats_from_ip(data.get("ip", ""))})

@app.route("/api/search/dfs", methods=["POST"])
def api_dfs():
    data = request.get_json()
    uri = data.get("threat_uri") or list(graph_dict.keys())[0]
    return jsonify({"chain": searcher.dfs_attack_chain(uri)})

@app.route("/api/search/astar", methods=["POST"])
def api_astar():
    data = request.get_json()
    return jsonify({"results": searcher.astar_similar_threats(data.get("threat_uri", ""), data.get("top_k", 5))})

@app.route("/api/csp/solve", methods=["POST"])
def api_csp():
    """Run CSP solver using mitigations loaded from the Ontology."""
    solver = CSPSolver(rdf_graph=kg.graph)
    return jsonify({"solutions": solver.solve(max_solutions=3)})

@app.route("/api/graph/data")
def api_graph_data():
    return jsonify(kg.get_graph_nodes_edges())

@app.route("/api/unify", methods=["POST"])
def api_unify():
    data = request.get_json()
    kb = KnowledgeBase(rdf_graph=kg.graph)
    return jsonify({"bindings": kb.unify(data.get("pattern1", []), data.get("pattern2", []))})

if __name__ == "__main__":
    app.run(debug=True, port=5001)