"""
MODULE 2: Ontology & RDF Knowledge Graph Manager
Loads OWL ontology, runs SPARQL queries, performs inference.
"""

import os
from rdflib import Graph, Namespace, RDF, RDFS, OWL, XSD, Literal, URIRef
from rdflib.plugins.sparql import prepareQuery

CS = Namespace("http://cybersec.kg/ontology#")
EX = Namespace("http://cybersec.kg/instance#")


class CyberSecKnowledgeGraph:
    """
    Manages the RDF knowledge graph for cyber security threats.
    Provides SPARQL query interface and inference capabilities.
    """

    def __init__(self, ontology_path=None):
        self.graph = Graph()
        self.graph.bind("cs", CS)
        self.graph.bind("ex", EX)
        self.graph.bind("owl", OWL)
        self.graph.bind("rdfs", RDFS)
        self.ontology_path = ontology_path
        self._loaded = False

    def load_ontology(self, path=None):
        """Load the OWL/Turtle ontology file."""
        p = path or self.ontology_path
        if p and os.path.exists(p):
            self.graph.parse(p, format="turtle")
            self._loaded = True
            self._apply_property_chain_inference()
            return True
        return False

    def _apply_property_chain_inference(self):
        """
        Apply property chain inference:
        hasIndicator ∘ indicatesThreat → classifiedAsThreat
        For each threat T: if T hasIndicator I and I indicatesThreat T2,
        then T classifiedAsThreat T2.
        """
        chain_query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        SELECT ?threat ?indicator ?classified_threat WHERE {
            ?threat cs:hasIndicator ?indicator .
            ?indicator cs:indicatesThreat ?classified_threat .
        }
        """
        results = self.graph.query(chain_query)
        count = 0
        for row in results:
            self.graph.add((row.threat, CS.classifiedAsThreat, row.classified_threat))
            count += 1
        return count

    def sparql_query(self, query_str):
        """Execute a raw SPARQL SELECT query and return results as list of dicts."""
        try:
            results = self.graph.query(query_str)
            output = []
            for row in results:
                record = {}
                for var in results.vars:
                    val = getattr(row, str(var), None)
                    record[str(var)] = str(val) if val is not None else ""
                output.append(record)
            return output
        except Exception as e:
            return [{"error": str(e)}]

    # ============================================================
    # PREDEFINED SPARQL QUERIES
    # ============================================================

    def get_all_threats(self):
        """Return all threat instances with key properties."""
        query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?threat ?label ?type ?severity ?confidence ?attempts ?timestamp WHERE {
            ?threat rdfs:label ?label .
            ?threat rdf:type ?type .
            ?type rdfs:subClassOf* cs:Threat .
            OPTIONAL { ?threat cs:severityScore ?severity }
            OPTIONAL { ?threat cs:confidenceScore ?confidence }
            OPTIONAL { ?threat cs:attemptCount ?attempts }
            OPTIONAL { ?threat cs:timestamp ?timestamp }
        }
        ORDER BY DESC(?severity)
        """
        return self.sparql_query(query)

    def get_phishing_attacks(self):
        """Get all phishing attacks."""
        query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?threat ?label ?severity ?confidence ?ip WHERE {
            ?threat rdf:type ?type .
            ?type rdfs:subClassOf* cs:PhishingAttack .
            ?threat rdfs:label ?label .
            OPTIONAL { ?threat cs:severityScore ?severity }
            OPTIONAL { ?threat cs:confidenceScore ?confidence }
            OPTIONAL { ?threat cs:originatesFromIP ?ipNode .
                       ?ipNode cs:ipValue ?ip }
        }
        ORDER BY DESC(?severity)
        """
        return self.sparql_query(query)

    def get_malware_threats(self):
        """Get all malware-type threats."""
        query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?threat ?label ?type ?severity ?system WHERE {
            ?threat rdf:type ?type .
            ?type rdfs:subClassOf* cs:Malware .
            ?threat rdfs:label ?label .
            OPTIONAL { ?threat cs:severityScore ?severity }
            OPTIONAL { ?threat cs:affectsSystem ?sys .
                       ?sys rdfs:label ?system }
        }
        ORDER BY DESC(?severity)
        """
        return self.sparql_query(query)

    def get_threats_by_ip(self, ip_value):
        """Find all threats originating from a specific IP."""
        query = f"""
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?threat ?label ?type ?severity ?confidence WHERE {{
            ?threat cs:originatesFromIP ?ipNode .
            ?ipNode cs:ipValue "{ip_value}" .
            ?threat rdfs:label ?label .
            ?threat rdf:type ?type .
            OPTIONAL {{ ?threat cs:severityScore ?severity }}
            OPTIONAL {{ ?threat cs:confidenceScore ?confidence }}
        }}
        ORDER BY DESC(?severity)
        """
        return self.sparql_query(query)

    def get_high_severity_threats(self, threshold=8.0):
        """Get all threats above a severity threshold."""
        query = f"""
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?threat ?label ?type ?severity ?mitigation WHERE {{
            ?threat rdfs:label ?label .
            ?threat rdf:type ?type .
            ?threat cs:severityScore ?severity .
            FILTER(?severity >= {threshold})
            OPTIONAL {{ ?threat cs:mitigatedBy ?mit .
                        ?mit rdfs:label ?mitigation }}
        }}
        ORDER BY DESC(?severity)
        """
        return self.sparql_query(query)

    def get_threats_by_category(self):
        """Group and count threats by category."""
        query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?type (COUNT(?threat) AS ?count) (AVG(?severity) AS ?avg_severity) WHERE {
            ?threat rdf:type ?type .
            ?type rdfs:subClassOf* cs:Threat .
            OPTIONAL { ?threat cs:severityScore ?severity }
        }
        GROUP BY ?type
        ORDER BY DESC(?count)
        """
        return self.sparql_query(query)

    def get_mitigations_for_threat(self, threat_label):
        """Get all mitigations for a specific threat."""
        query = f"""
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?threat ?mit_label ?mit_type WHERE {{
            ?threat rdfs:label "{threat_label}" .
            ?threat cs:mitigatedBy ?mit .
            ?mit rdfs:label ?mit_label .
            OPTIONAL {{ ?mit cs:mitigationType ?mit_type }}
        }}
        """
        return self.sparql_query(query)

    def get_brute_force_attacks(self):
        """Get all brute force attacks with attempt counts."""
        query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?threat ?label ?attempts ?severity ?ip WHERE {
            ?threat rdf:type cs:BruteForceAttack .
            ?threat rdfs:label ?label .
            OPTIONAL { ?threat cs:attemptCount ?attempts }
            OPTIONAL { ?threat cs:severityScore ?severity }
            OPTIONAL { ?threat cs:originatesFromIP ?ipNode .
                       ?ipNode cs:ipValue ?ip }
        }
        ORDER BY DESC(?attempts)
        """
        return self.sparql_query(query)

    def get_property_chain_inferences(self):
        """Get all classifiedAsThreat inferences from property chain."""
        query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?source ?source_label ?classified ?classified_label WHERE {
            ?source cs:classifiedAsThreat ?classified .
            ?source rdfs:label ?source_label .
            ?classified rdfs:label ?classified_label .
        }
        """
        return self.sparql_query(query)

    def get_graph_nodes_edges(self):
        """
        Extract graph structure for visualization.
        Returns nodes and edges for D3.js/Cytoscape rendering.
        """
        nodes = {}
        edges = []

        # Get threat nodes
        threat_query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?uri ?label ?type ?severity WHERE {
            ?uri rdf:type ?type .
            ?type rdfs:subClassOf* cs:Threat .
            ?uri rdfs:label ?label .
            OPTIONAL { ?uri cs:severityScore ?severity }
        }
        """
        threats = self.sparql_query(threat_query)
        for t in threats:
            uri = t.get('uri', '')
            type_uri = t.get('type', '')
            type_name = type_uri.split('#')[-1] if '#' in type_uri else type_uri.split('/')[-1]
            if uri and uri not in nodes:
                nodes[uri] = {
                    'id': uri,
                    'label': t.get('label', uri.split('/')[-1]),
                    'type': type_name,
                    'severity': float(t.get('severity', 5.0)) if t.get('severity') else 5.0,
                    'group': 'threat'
                }

        # Get edges (relationships)
        rel_query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?src ?rel ?tgt WHERE {
            ?src cs:relatedTo ?tgt .
            BIND("relatedTo" AS ?rel)
        }
        """
        rels = self.sparql_query(rel_query)
        for r in rels:
            src = r.get('src', '')
            tgt = r.get('tgt', '')
            if src and tgt and src in nodes and tgt in nodes:
                edges.append({'source': src, 'target': tgt, 'relation': r.get('rel', 'related')})

        return {
            'nodes': list(nodes.values()),
            'edges': edges
        }

    def get_statistics(self):
        """Compute knowledge graph statistics."""
        total_triples = len(self.graph)
        threats = self.get_all_threats()

        unique_threats = set()
        severity_sum = 0
        severity_count = 0
        for t in threats:
            uri = t.get('threat', '')
            if uri and uri not in unique_threats:
                unique_threats.add(uri)
                sev = t.get('severity', '')
                if sev:
                    try:
                        severity_sum += float(sev)
                        severity_count += 1
                    except:
                        pass

        avg_severity = round(severity_sum / severity_count, 2) if severity_count > 0 else 0

        category_query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT (COUNT(DISTINCT ?mit) AS ?count) WHERE {
            ?mit rdf:type cs:Mitigation .
        }
        """
        mit_result = self.sparql_query(category_query)
        mit_count = int(mit_result[0].get('count', 0)) if mit_result else 0

        return {
            'total_triples': total_triples,
            'total_threats': len(unique_threats),
            'avg_severity': avg_severity,
            'total_mitigations': mit_count,
            'ontology_loaded': self._loaded
        }

    def build_graph_dict(self):
        """
        Build an adjacency dict for search algorithms.
        Returns: {uri: {label, type, severity, ip, vuln, related: [...]}}
        """
        threat_query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        SELECT ?uri ?label ?type ?severity ?ip ?vuln WHERE {
            ?uri rdf:type ?type .
            ?type rdfs:subClassOf* cs:Threat .
            ?uri rdfs:label ?label .
            OPTIONAL { ?uri cs:severityScore ?severity }
            OPTIONAL { ?uri cs:originatesFromIP ?ipNode . ?ipNode cs:ipValue ?ip }
            OPTIONAL { ?uri cs:targetsVulnerability ?vulnNode . ?vulnNode rdfs:label ?vuln }
        }
        """
        threats = self.sparql_query(threat_query)

        rel_query = """
        PREFIX cs: <http://cybersec.kg/ontology#>
        SELECT ?src ?tgt WHERE { ?src cs:relatedTo ?tgt . }
        """
        rels = self.sparql_query(rel_query)

        graph_dict = {}
        for t in threats:
            uri = t.get('uri', '')
            if not uri:
                continue
            type_uri = t.get('type', '')
            type_name = type_uri.split('#')[-1] if '#' in type_uri else type_uri.split('/')[-1]
            graph_dict[uri] = {
                'label': t.get('label', ''),
                'type': type_name,
                'severity': float(t.get('severity', 5.0)) if t.get('severity') else 5.0,
                'ip': t.get('ip', ''),
                'vuln': t.get('vuln', ''),
                'related': []
            }

        for r in rels:
            src = r.get('src', '')
            tgt = r.get('tgt', '')
            if src in graph_dict and tgt in graph_dict:
                if tgt not in graph_dict[src]['related']:
                    graph_dict[src]['related'].append(tgt)

        return graph_dict