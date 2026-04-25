"""
BACKEND: Flask API for Intelligent Cyber Security Knowledge System
Exposes REST endpoints for all AI modules.
"""

import os
import json
from flask import Flask, render_template, request, jsonify

# Module imports
from modules.knowledge_graph import CyberSecKnowledgeGraph
from modules.search_algorithms import ThreatGraphSearch
from modules.expert_system import KnowledgeBase, CertaintyFactor, CSPSolver

app = Flask(__name__)

# ============================================================
# INITIALIZE KNOWLEDGE GRAPH
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ONTOLOGY_PATH = os.path.join(BASE_DIR, "ontology", "cybersec.ttl")

kg = CyberSecKnowledgeGraph(ontology_path=ONTOLOGY_PATH)
kg.load_ontology()
graph_dict = kg.build_graph_dict()
searcher = ThreatGraphSearch(graph_dict)

# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyzer")
def analyzer():
    return render_template("analyzer.html")

@app.route("/query")
def query_page():
    return render_template("query.html")

@app.route("/recommendations")
def recommendations():
    return render_template("recommendations.html")

@app.route("/graph")
def graph_page():
    return render_template("graph.html")

@app.route("/csp")
def csp_page():
    return render_template("csp.html")

# ============================================================
# API ENDPOINTS
# ============================================================

@app.route("/api/stats")
def api_stats():
    """Return knowledge graph statistics."""
    stats = kg.get_statistics()
    return jsonify(stats)

@app.route("/api/threats/all")
def api_all_threats():
    """Get all threats from knowledge graph."""
    threats = kg.get_all_threats()
    # Deduplicate by URI
    seen = set()
    unique = []
    for t in threats:
        uri = t.get('threat', '')
        if uri and uri not in seen:
            seen.add(uri)
            t['threat_id'] = uri.split('/')[-1]
            t_type = t.get('type', '')
            t['type_short'] = t_type.split('#')[-1] if '#' in t_type else t_type.split('/')[-1]
            unique.append(t)
    return jsonify(unique)

@app.route("/api/threats/phishing")
def api_phishing():
    return jsonify(kg.get_phishing_attacks())

@app.route("/api/threats/malware")
def api_malware():
    return jsonify(kg.get_malware_threats())

@app.route("/api/threats/brute-force")
def api_brute_force():
    return jsonify(kg.get_brute_force_attacks())

@app.route("/api/threats/high-severity")
def api_high_severity():
    threshold = float(request.args.get("threshold", 8.0))
    return jsonify(kg.get_high_severity_threats(threshold))

@app.route("/api/threats/by-ip")
def api_threats_by_ip():
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    return jsonify(kg.get_threats_by_ip(ip))

@app.route("/api/threats/categories")
def api_categories():
    results = kg.get_threats_by_category()
    categories = {}
    for r in results:
        type_uri = r.get('type', '')
        type_name = type_uri.split('#')[-1] if '#' in type_uri else type_uri.split('/')[-1]
        if type_name and type_name not in categories:
            categories[type_name] = {
                'count': int(r.get('count', 0)),
                'avg_severity': round(float(r.get('avg_severity', 0)), 2) if r.get('avg_severity') else 0
            }
    return jsonify(categories)

@app.route("/api/inference/property-chain")
def api_property_chain():
    return jsonify(kg.get_property_chain_inferences())

@app.route("/api/sparql", methods=["POST"])
def api_sparql():
    """Execute custom SPARQL query."""
    data = request.get_json()
    query = data.get("query", "")
    if not query:
        return jsonify({"error": "Query required"}), 400
    results = kg.sparql_query(query)
    return jsonify({"results": results, "count": len(results)})

# ============================================================
# THREAT ANALYZER API
# ============================================================

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Main threat analysis endpoint.
    Accepts: IP, login_attempts, url, and optional flags.
    Returns: Expert system conclusions with certainty factors.
    """
    data = request.get_json()

    ip = data.get("ip", "")
    login_attempts = int(data.get("login_attempts", 0))
    url = data.get("url", "")
    payload = data.get("payload", False)
    email_link = data.get("email_link", False)

    # Known suspicious IP ranges (simplified)
    suspicious_ips = ["185.220.", "45.33.", "203.0.", "198.51."]
    is_suspicious_ip = any(ip.startswith(s) for s in suspicious_ips)

    # Known malicious URL patterns
    malicious_patterns = ["phish", "secure-login", "verify-account", "free-", "click-here", "bit.ly", "tinyurl"]
    is_malicious_url = any(p in url.lower() for p in malicious_patterns) if url else False

    # Build knowledge base
    kb = KnowledgeBase()
    kb.assert_fact("failed_login_attempts", login_attempts)
    kb.assert_fact("suspicious_ip", is_suspicious_ip)
    kb.assert_fact("url_is_malicious", is_malicious_url)
    kb.assert_fact("email_contains_link", email_link or bool(url))
    kb.assert_fact("suspicious_payload", payload)
    kb.assert_fact("mass_file_encryption", payload and login_attempts == 0)
    kb.assert_fact("sql_keywords_in_input", any(k in url.lower() for k in ["select", "union", "drop", "insert", "--", "'"]) if url else False)
    kb.assert_fact("unusual_db_queries", is_suspicious_ip and bool(url))
    kb.assert_fact("request_rate", login_attempts * 10 if login_attempts > 100 else 0)
    kb.assert_fact("multiple_source_ips", login_attempts > 500)
    kb.assert_fact("unknown_exploit_signature", payload and is_suspicious_ip)
    kb.assert_fact("high_severity_cve", payload)
    kb.assert_fact("targeted_individual", email_link and not is_malicious_url)
    kb.assert_fact("impersonation_detected", email_link and login_attempts < 5)
    kb.assert_fact("ssl_certificate_mismatch", bool(url) and "https" not in url.lower())
    kb.assert_fact("traffic_rerouted", is_suspicious_ip and login_attempts > 0)
    kb.assert_fact("suspicious_process", payload)
    kb.assert_fact("antivirus_alert", payload and is_suspicious_ip)
    kb.assert_fact("large_data_transfer", login_attempts > 1000)
    kb.assert_fact("unusual_destination_ip", is_suspicious_ip and login_attempts > 50)

    # Run forward chaining
    conclusions, fired_rules = kb.forward_chain()

    # Also get RDF-based threats from this IP
    rdf_threats = kg.get_threats_by_ip(ip) if ip else []

    # BFS from IP
    bfs_results = searcher.bfs_threats_from_ip(ip) if ip else []

    return jsonify({
        "input": {
            "ip": ip,
            "login_attempts": login_attempts,
            "url": url,
            "is_suspicious_ip": is_suspicious_ip,
            "is_malicious_url": is_malicious_url
        },
        "expert_system": {
            "conclusions": conclusions,
            "fired_rules": fired_rules,
            "facts_asserted": len(kb.facts)
        },
        "rdf_threats": rdf_threats[:5],
        "bfs_related": bfs_results[:5],
        "total_threats_detected": len(conclusions)
    })

@app.route("/api/backward-chain", methods=["POST"])
def api_backward_chain():
    """Backward chaining: given a threat type, find required conditions."""
    data = request.get_json()
    goal = data.get("goal", "")
    facts = data.get("facts", {})

    kb = KnowledgeBase()
    for k, v in facts.items():
        kb.assert_fact(k, v)

    result = kb.backward_chain(goal)
    return jsonify(result)

# ============================================================
# SEARCH ALGORITHM APIS
# ============================================================

@app.route("/api/search/bfs", methods=["POST"])
def api_bfs():
    """BFS: Find all threats connected to a given IP."""
    data = request.get_json()
    ip = data.get("ip", "")
    results = searcher.bfs_threats_from_ip(ip)
    return jsonify({
        "algorithm": "BFS",
        "query_ip": ip,
        "threats_found": len(results),
        "results": results
    })

@app.route("/api/search/dfs", methods=["POST"])
def api_dfs():
    """DFS: Explore full attack chain from a threat."""
    data = request.get_json()
    threat_uri = data.get("threat_uri", "")
    if not threat_uri:
        # Find first threat in graph
        uris = list(graph_dict.keys())
        threat_uri = uris[0] if uris else ""

    chain = searcher.dfs_attack_chain(threat_uri)
    return jsonify({
        "algorithm": "DFS",
        "start_threat": threat_uri,
        "chain_length": len(chain),
        "attack_chain": chain
    })

@app.route("/api/search/astar", methods=["POST"])
def api_astar():
    """A*: Find similar threats using heuristic search."""
    data = request.get_json()
    threat_uri = data.get("threat_uri", "")
    top_k = int(data.get("top_k", 5))

    similar = searcher.astar_similar_threats(threat_uri, top_k)
    return jsonify({
        "algorithm": "A*",
        "query_threat": threat_uri,
        "results": similar
    })

@app.route("/api/threats/list-uris")
def api_list_uris():
    """List all threat URIs for frontend dropdowns."""
    uris = [
        {"uri": uri, "label": data.get("label", uri.split("/")[-1]), "type": data.get("type", "")}
        for uri, data in graph_dict.items()
    ]
    return jsonify(uris)

# ============================================================
# CSP SOLVER API
# ============================================================

@app.route("/api/csp/solve", methods=["POST"])
def api_csp():
    """Run CSP solver for security planning."""
    solver = CSPSolver()
    solutions = solver.solve(max_solutions=3)
    return jsonify({
        "solutions": solutions,
        "total_found": len(solutions),
        "measures_available": len(CSPSolver.SECURITY_MEASURES)
    })

# ============================================================
# GRAPH VISUALIZATION API
# ============================================================

@app.route("/api/graph/data")
def api_graph_data():
    """Return graph data for visualization."""
    data = kg.get_graph_nodes_edges()
    return jsonify(data)

# ============================================================
# UNIFICATION API
# ============================================================

@app.route("/api/unify", methods=["POST"])
def api_unify():
    """Demonstrate unification logic."""
    data = request.get_json()
    pattern1 = data.get("pattern1", [])
    pattern2 = data.get("pattern2", [])

    kb = KnowledgeBase()
    bindings = kb.unify(pattern1, pattern2)

    return jsonify({
        "pattern1": pattern1,
        "pattern2": pattern2,
        "bindings": bindings,
        "unified": bool(bindings) or pattern1 == pattern2
    })

# ============================================================
# PREDEFINED QUERY TEMPLATES
# ============================================================

QUERY_TEMPLATES = {
    "all_phishing": """PREFIX cs: <http://cybersec.kg/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT ?threat ?label ?severity WHERE {
    ?threat rdf:type ?type .
    ?type rdfs:subClassOf* cs:PhishingAttack .
    ?threat rdfs:label ?label .
    OPTIONAL { ?threat cs:severityScore ?severity }
} ORDER BY DESC(?severity)""",

    "all_malware": """PREFIX cs: <http://cybersec.kg/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT ?threat ?label ?type ?severity WHERE {
    ?threat rdf:type ?type .
    ?type rdfs:subClassOf* cs:Malware .
    ?threat rdfs:label ?label .
    OPTIONAL { ?threat cs:severityScore ?severity }
} ORDER BY DESC(?severity)""",

    "high_severity": """PREFIX cs: <http://cybersec.kg/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?threat ?label ?severity WHERE {
    ?threat rdfs:label ?label .
    ?threat cs:severityScore ?severity .
    FILTER(?severity >= 9.0)
} ORDER BY DESC(?severity)""",

    "threat_count_by_type": """PREFIX cs: <http://cybersec.kg/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?type (COUNT(?t) AS ?count) WHERE {
    ?t rdf:type ?type .
    ?type rdfs:subClassOf* cs:Threat .
} GROUP BY ?type ORDER BY DESC(?count)""",

    "property_chain": """PREFIX cs: <http://cybersec.kg/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?src ?src_label ?classified ?classified_label WHERE {
    ?src cs:classifiedAsThreat ?classified .
    ?src rdfs:label ?src_label .
    ?classified rdfs:label ?classified_label .
}"""
}

@app.route("/api/queries/templates")
def api_query_templates():
    return jsonify(QUERY_TEMPLATES)

if __name__ == "__main__":
    app.run(debug=True, port=5001)