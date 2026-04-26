"""
MODULE 4, 5 & 6: Integrated Expert System & CSP Solver
"""
import itertools

class CertaintyFactor:
    @staticmethod
    def combine(cf1, cf2):
        if cf1 >= 0 and cf2 >= 0: return cf1 + cf2 * (1 - cf1)
        elif cf1 < 0 and cf2 < 0: return cf1 + cf2 * (1 + cf1)
        else:
            denom = 1 - min(abs(cf1), abs(cf2))
            return (cf1 + cf2) / (denom if denom != 0 else 1)

    @staticmethod
    def combine_multiple(cfs):
        if not cfs: return 0.0
        res = cfs[0]
        for cf in cfs[1:]: res = CertaintyFactor.combine(res, cf)
        return round(res, 4)

    @staticmethod
    def classify(cf):
        if cf < 0.4: return "Unlikely"
        if cf < 0.7: return "Likely"
        return "Highly Confident"

class KnowledgeBase:
    def __init__(self, rdf_graph=None):
        self.facts = {}
        self.graph = rdf_graph
        # Synchronized with your .ttl Class Names
        self.logic_map = {
            "BruteForceAttack": [("failed_login_attempts", ">", 5), ("suspicious_ip", "==", True)],
            "PhishingAttack": [("url_is_malicious", "==", True), ("email_contains_link", "==", True)],
            "Ransomware": [("suspicious_payload", "==", True), ("mass_file_encryption", "==", True)],
            "SQLInjection": [("sql_keywords_in_input", "==", True), ("unusual_db_queries", "==", True)],
            "DDoSAttack": [("request_rate", ">", 10000), ("multiple_source_ips", "==", True)],
            "ZeroDay": [("unknown_exploit_signature", "==", True), ("high_severity_cve", "==", True)],
            "SpearPhishing": [("targeted_individual", "==", True), ("impersonation_detected", "==", True)],
            "ManInTheMiddle": [("ssl_certificate_mismatch", "==", True), ("traffic_rerouted", "==", True)],
            "Malware": [("suspicious_process", "==", True), ("antivirus_alert", "==", True)]
        }
        self.rules = self._sync_rules()

    def _sync_rules(self):
        rules = []
        for c_name, conds in self.logic_map.items():
            label, sev, mits = c_name, 5.0, []
            if self.graph:
                # Query ontology for metadata
                q = f"PREFIX cs: <http://cybersec.kg/ontology#> PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#> " \
                    f"SELECT ?l ?s ?m WHERE {{ ?t a cs:{c_name} ; rdfs:label ?l ; cs:severityScore ?s . " \
                    f"OPTIONAL {{ ?t cs:mitigatedBy ?mit . ?mit rdfs:label ?m }} }}"
                res = self.graph.query(q)
                for row in res:
                    label, sev = str(row.l), float(row.s)
                    if row.m: mits.append(str(row.m))
            
            if not mits: mits = ["Generic Firewall Rules", "Security Awareness Training"]
            rules.append({"id": c_name, "name": label, "conditions": conds, "conclusion": c_name, "cf": 0.9, "severity": sev, "mitigation": list(set(mits))})
        return rules

    def assert_fact(self, p, v): self.facts[p] = v

    def _evaluate_condition(self, cond):
        f_val = self.facts.get(cond[0])
        if f_val is None: return False, 0.0
        if cond[1] == ">": return f_val > cond[2], 0.8
        if cond[1] == "==": return f_val == cond[2], 1.0
        return False, 0.0

    def forward_chain(self):
        concl = []
        for r in self.rules:
            res = [self._evaluate_condition(c) for c in r["conditions"]]
            if all(x[0] for x in res):
                cf = CertaintyFactor.combine(CertaintyFactor.combine_multiple([x[1] for x in res]), r["cf"])
                concl.append({
                    "rule_id": r["id"], "rule_name": r["name"], "threat_type": r["conclusion"], 
                    "certainty_factor": cf, "cf_classification": CertaintyFactor.classify(cf), 
                    "severity": r["severity"], "mitigation": r["mitigation"],
                    "explanation": [f"{'✓' if self._evaluate_condition(c)[0] else '✗'} {c[0]}" for c in r["conditions"]]
                })
        return sorted(concl, key=lambda x: x["certainty_factor"], reverse=True), [c["rule_id"] for c in concl]

    def backward_chain(self, goal):
        r = next((x for x in self.rules if x["id"].lower() == goal.lower()), None)
        if not r: return {"found": False, "message": "Goal not found"}
        miss = [f"{c[0]} {c[1]} {c[2]}" for c in r["conditions"] if not self._evaluate_condition(c)[0]]
        return {"goal": goal, "confirmed": len(miss) == 0, "rules_checked": [{"rule_id": r["id"], "rule_name": r["name"], "satisfied_conditions": [], "unsatisfied_conditions": miss}]}

    def unify(self, p1, p2):
        if p1 == p2: return {}
        if isinstance(p1, str) and p1.startswith('?'): return {p1: p2}
        if isinstance(p2, str) and p2.startswith('?'): return {p2: p1}
        if isinstance(p1, list) and isinstance(p2, list) and len(p1) == len(p2):
            b = {}
            for s1, s2 in zip(p1, p2):
                u = self.unify(s1, s2); 
                if u is None: return None
                b.update(u)
            return b
        return None

class CSPSolver:
    def __init__(self, rdf_graph=None):
        self.graph = rdf_graph
        self.SECURITY_MEASURES = self._load_measures()

    def _load_measures(self):
        if not self.graph: return [{"name": "Default Firewall", "type": "Preventive"}]
        q = "PREFIX cs: <http://cybersec.kg/ontology#> PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#> " \
            "SELECT ?l ?t WHERE { ?m a cs:Mitigation ; rdfs:label ?l ; cs:mitigationType ?t . }"
        return [{"name": str(row.l), "type": str(row.t)} for row in self.graph.query(q)]

    def solve(self, max_solutions=3):
        return [{"solution_id": 1, "measures": self.SECURITY_MEASURES[:5], "types": list(set(m["type"] for m in self.SECURITY_MEASURES[:5]))}]