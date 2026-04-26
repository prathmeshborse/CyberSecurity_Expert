"""
MODULE 2: Ontology & RDF Knowledge Graph Manager (Robust Version)
Handles cases where ontology instances might have missing properties.
"""

import os
from rdflib import Graph, Namespace, RDF, RDFS, OWL, URIRef

CS = Namespace("http://cybersec.kg/ontology#")
EX = Namespace("http://cybersec.kg/instance#")

class CyberSecKnowledgeGraph:
    def __init__(self, ontology_path=None):
        self.graph = Graph()
        self.graph.bind("cs", CS); self.graph.bind("ex", EX)
        self.ontology_path = ontology_path
        self._loaded = False

    def load_ontology(self, path=None):
        p = path or self.ontology_path
        if p and os.path.exists(p):
            self.graph.parse(p, format="turtle")
            self._loaded = True
            self._apply_property_chain_inference()
            return True
        return False

    def _apply_property_chain_inference(self):
        q = "PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?e ?t WHERE { ?e cs:hasIndicator ?i . ?i cs:indicatesThreat ?t . }"
        for row in self.graph.query(q):
            self.graph.add((row.e, CS.classifiedAsThreat, row.t))

    def sparql_query(self, query_str):
        try:
            results = self.graph.query(query_str)
            return [{str(var): str(getattr(row, str(var), "")) for var in results.vars} for row in results]
        except Exception as e:
            return [{"error": str(e)}]

    # ============================================================
    # API METHODS (REQUIRED BY app.py)
    # ============================================================

    def get_all_threats(self):
        return self.sparql_query("""
            PREFIX cs: <http://cybersec.kg/ontology#>
            SELECT ?threat ?label ?type ?severity WHERE {
                ?threat a ?type . ?type rdfs:subClassOf* cs:Threat .
                ?threat rdfs:label ?label . OPTIONAL { ?threat cs:severityScore ?severity }
            } ORDER BY DESC(?severity)""")

    def get_phishing_attacks(self):
        return self.sparql_query("PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?threat ?label ?severity WHERE { ?threat a/rdfs:subClassOf* cs:PhishingAttack ; rdfs:label ?label . OPTIONAL {?threat cs:severityScore ?severity} }")

    def get_malware_threats(self):
        return self.sparql_query("PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?threat ?label ?severity WHERE { ?threat a/rdfs:subClassOf* cs:Malware ; rdfs:label ?label . OPTIONAL {?threat cs:severityScore ?severity} }")

    def get_brute_force_attacks(self):
        return self.sparql_query("PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?threat ?label ?attempts WHERE { ?threat a cs:BruteForceAttack ; rdfs:label ?label . OPTIONAL {?threat cs:attemptCount ?attempts} }")

    def get_high_severity_threats(self, threshold=8.0):
        return self.sparql_query(f"PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?threat ?label ?severity WHERE {{ ?threat cs:severityScore ?severity ; rdfs:label ?label . FILTER(?severity >= {threshold}) }}")

    def get_threats_by_ip(self, ip_value):
        return self.sparql_query(f'PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?threat ?label WHERE {{ ?threat cs:originatesFromIP/cs:ipValue "{ip_value}" ; rdfs:label ?label . }}')

    def get_threats_by_category(self):
        return self.sparql_query("PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?type (COUNT(?t) as ?count) (AVG(?s) as ?avg_severity) WHERE { ?t a ?type . ?type rdfs:subClassOf* cs:Threat . OPTIONAL {?t cs:severityScore ?s} } GROUP BY ?type")

    def get_property_chain_inferences(self):
        return self.sparql_query("PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?source ?source_label ?classified ?classified_label WHERE { ?source cs:classifiedAsThreat ?classified ; rdfs:label ?source_label . ?classified rdfs:label ?classified_label . }")

    def get_statistics(self):
        return {'total_triples': len(self.graph), 'total_threats': len(self.get_all_threats()), 'ontology_loaded': self._loaded}

    # ============================================================
    # FIXED DATA BRIDGE
    # ============================================================

    def build_graph_dict(self):
        """Creates the adjacency structure for Search. Handles missing IPs safely."""
        # Use one efficient query to get all details including OPTIONAL IP
        query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        SELECT ?threat ?label ?type ?severity ?ip WHERE {
            ?threat a ?type . ?type rdfs:subClassOf* cs:Threat .
            ?threat rdfs:label ?label .
            OPTIONAL { ?threat cs:severityScore ?severity }
            OPTIONAL { ?threat cs:originatesFromIP/cs:ipValue ?ip }
        }
        """
        results = self.sparql_query(query)
        graph_dict = {}
        
        for t in results:
            uri = t['threat']
            graph_dict[uri] = {
                'label': t['label'],
                'type': t['type'].split('#')[-1],
                'severity': float(t['severity']) if t['severity'] else 5.0,
                'ip': t['ip'],  # This will now just be an empty string if not found
                'related': []
            }
        
        # Add relationships
        rel_query = "PREFIX cs: <http://cybersec.kg/ontology#> SELECT ?s ?t WHERE { ?s cs:relatedTo ?t }"
        for r in self.sparql_query(rel_query):
            if r['s'] in graph_dict:
                graph_dict[r['s']]['related'].append(r['t'])
                
        return graph_dict

    def get_graph_nodes_edges(self):
        g = self.build_graph_dict()
        nodes = [{'id': u, 'label': d['label'], 'group': d['type']} for u, d in g.items()]
        edges = [{'source': u, 'target': r} for u, d in g.items() for r in d['related']]
        return {'nodes': nodes, 'edges': edges}