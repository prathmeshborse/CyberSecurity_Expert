"""
MODULE 4 & 6: Expert System with Inference Rules and Uncertainty Handling
Implements forward chaining, backward chaining, unification, and MYCIN-style certainty factors.
"""


class CertaintyFactor:
    """
    MYCIN-style Certainty Factor model.
    Combines evidence to compute overall confidence.
    """

    @staticmethod
    def combine(cf1, cf2):
        """
        Combine two certainty factors:
        - Both positive: CF = CF1 + CF2*(1 - CF1)
        - Both negative: CF = CF1 + CF2*(1 + CF1)
        - Mixed signs:   CF = (CF1 + CF2) / (1 - min(|CF1|, |CF2|))
        """
        if cf1 >= 0 and cf2 >= 0:
            return cf1 + cf2 * (1 - cf1)
        elif cf1 < 0 and cf2 < 0:
            return cf1 + cf2 * (1 + cf1)
        else:
            denom = 1 - min(abs(cf1), abs(cf2))
            if denom == 0:
                return 0
            return (cf1 + cf2) / denom

    @staticmethod
    def combine_multiple(cfs):
        """Combine a list of certainty factors sequentially."""
        if not cfs:
            return 0.0
        result = cfs[0]
        for cf in cfs[1:]:
            result = CertaintyFactor.combine(result, cf)
        return round(result, 4)

    @staticmethod
    def classify(cf):
        """
        Classify confidence level:
        < 0.0  → Contradicted
        0.0    → Unknown
        0-0.2  → Very unlikely
        0.2-0.4 → Unlikely
        0.4-0.6 → Uncertain
        0.6-0.8 → Likely
        0.8-1.0 → Highly confident
        """
        if cf < 0:
            return "Contradicted"
        elif cf == 0:
            return "Unknown"
        elif cf < 0.2:
            return "Very Unlikely"
        elif cf < 0.4:
            return "Unlikely"
        elif cf < 0.5:
            return "Uncertain"
        elif cf < 0.6:
            return "Possible"
        elif cf < 0.8:
            return "Likely"
        else:
            return "Highly Confident"


class KnowledgeBase:
    """
    Rule-based knowledge base for cyber threat detection.
    """

    def __init__(self):
        # Facts: {predicate: value}
        self.facts = {}
        # Inferred conclusions: [{threat, cf, explanation}]
        self.conclusions = []
        # Rules definition
        self.rules = self._define_rules()

    def _define_rules(self):
        """Define expert system rules with certainty factors."""
        return [
            {
                "id": "R001",
                "name": "Brute Force Detection",
                "conditions": [
                    ("failed_login_attempts", ">", 5),
                    ("suspicious_ip", "==", True)
                ],
                "conclusion": "BruteForceAttack",
                "cf": 0.92,
                "severity": 7.0,
                "mitigation": ["Multi-Factor Authentication", "Firewall Rules", "Account Lockout Policy"]
            },
            {
                "id": "R002",
                "name": "Phishing Detection",
                "conditions": [
                    ("url_is_malicious", "==", True),
                    ("email_contains_link", "==", True)
                ],
                "conclusion": "PhishingAttack",
                "cf": 0.88,
                "severity": 7.5,
                "mitigation": ["Email Filtering", "Security Awareness Training", "Anti-Phishing Tools"]
            },
            {
                "id": "R003",
                "name": "Ransomware Detection",
                "conditions": [
                    ("suspicious_payload", "==", True),
                    ("mass_file_encryption", "==", True)
                ],
                "conclusion": "Ransomware",
                "cf": 0.95,
                "severity": 9.5,
                "mitigation": ["Regular Backups", "Antivirus Software", "Patch Management"]
            },
            {
                "id": "R004",
                "name": "SQL Injection Detection",
                "conditions": [
                    ("sql_keywords_in_input", "==", True),
                    ("unusual_db_queries", "==", True)
                ],
                "conclusion": "SQLInjection",
                "cf": 0.97,
                "severity": 9.1,
                "mitigation": ["Web Application Firewall", "Input Validation", "Prepared Statements"]
            },
            {
                "id": "R005",
                "name": "DDoS Detection",
                "conditions": [
                    ("request_rate", ">", 10000),
                    ("multiple_source_ips", "==", True)
                ],
                "conclusion": "DDoSAttack",
                "cf": 0.85,
                "severity": 8.2,
                "mitigation": ["Firewall Rules", "Rate Limiting", "CDN Protection"]
            },
            {
                "id": "R006",
                "name": "Zero-Day Exploit Detection",
                "conditions": [
                    ("unknown_exploit_signature", "==", True),
                    ("high_severity_cve", "==", True)
                ],
                "conclusion": "ZeroDayExploit",
                "cf": 0.78,
                "severity": 10.0,
                "mitigation": ["Emergency Patching", "Intrusion Detection System", "Network Isolation"]
            },
            {
                "id": "R007",
                "name": "Spear Phishing Detection",
                "conditions": [
                    ("targeted_individual", "==", True),
                    ("impersonation_detected", "==", True),
                    ("email_contains_link", "==", True)
                ],
                "conclusion": "SpearPhishing",
                "cf": 0.91,
                "severity": 8.8,
                "mitigation": ["DMARC/SPF/DKIM", "Email Authentication", "Executive Training"]
            },
            {
                "id": "R008",
                "name": "MITM Attack Detection",
                "conditions": [
                    ("ssl_certificate_mismatch", "==", True),
                    ("traffic_rerouted", "==", True)
                ],
                "conclusion": "ManInTheMiddleAttack",
                "cf": 0.83,
                "severity": 7.9,
                "mitigation": ["Data Encryption", "Certificate Pinning", "VPN Usage"]
            },
            {
                "id": "R009",
                "name": "Malware General Detection",
                "conditions": [
                    ("suspicious_process", "==", True),
                    ("antivirus_alert", "==", True)
                ],
                "conclusion": "Malware",
                "cf": 0.89,
                "severity": 8.0,
                "mitigation": ["Antivirus Software", "Endpoint Protection", "System Isolation"]
            },
            {
                "id": "R010",
                "name": "Data Exfiltration Detection",
                "conditions": [
                    ("large_data_transfer", "==", True),
                    ("unusual_destination_ip", "==", True)
                ],
                "conclusion": "DataExfiltration",
                "cf": 0.87,
                "severity": 9.0,
                "mitigation": ["Data Loss Prevention", "Network Monitoring", "Access Controls"]
            }
        ]

    def assert_fact(self, predicate, value):
        """Add a fact to the knowledge base."""
        self.facts[predicate] = value

    def _evaluate_condition(self, condition):
        """Evaluate a single condition against current facts."""
        predicate, operator, threshold = condition
        fact_value = self.facts.get(predicate)

        if fact_value is None:
            return False, 0.0

        if operator == ">":
            return fact_value > threshold, 0.9 if fact_value > threshold * 2 else 0.7
        elif operator == "<":
            return fact_value < threshold, 0.8
        elif operator == "==":
            return fact_value == threshold, 1.0
        elif operator == ">=":
            return fact_value >= threshold, 0.85
        return False, 0.0

    def forward_chain(self):
        """
        Forward Chaining: Data-driven inference.
        Fires all applicable rules and collects conclusions.
        """
        self.conclusions = []
        fired_rules = []

        for rule in self.rules:
            condition_results = []
            all_true = True
            explanation_parts = []

            for condition in rule["conditions"]:
                is_true, local_cf = self._evaluate_condition(condition)
                condition_results.append(local_cf if is_true else 0.0)
                explanation_parts.append(
                    f"{'✓' if is_true else '✗'} {condition[0]} {condition[1]} {condition[2]}"
                )
                if not is_true:
                    all_true = False

            if all_true and condition_results:
                # Combine condition CFs with rule CF
                combined_cf = CertaintyFactor.combine_multiple(condition_results)
                final_cf = CertaintyFactor.combine(combined_cf, rule["cf"])
                final_cf = round(min(final_cf, 1.0), 4)

                self.conclusions.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "threat_type": rule["conclusion"],
                    "certainty_factor": final_cf,
                    "cf_classification": CertaintyFactor.classify(final_cf),
                    "severity": rule["severity"],
                    "mitigation": rule["mitigation"],
                    "explanation": explanation_parts,
                    "is_uncertain": final_cf < 0.5
                })
                fired_rules.append(rule["id"])

        # Sort by CF descending
        self.conclusions.sort(key=lambda x: x["certainty_factor"], reverse=True)
        return self.conclusions, fired_rules

    def backward_chain(self, goal_threat):
        """
        Backward Chaining: Goal-driven inference.
        Finds which conditions are needed to confirm a given threat type.
        """
        required_conditions = []
        matching_rules = []

        for rule in self.rules:
            if rule["conclusion"].lower() == goal_threat.lower():
                matching_rules.append(rule)

        if not matching_rules:
            return {
                "goal": goal_threat,
                "found": False,
                "message": f"No rules found for threat: {goal_threat}",
                "required_conditions": []
            }

        for rule in matching_rules:
            satisfied = []
            unsatisfied = []
            partial_cfs = []

            for condition in rule["conditions"]:
                is_true, local_cf = self._evaluate_condition(condition)
                if is_true:
                    satisfied.append(f"{condition[0]} {condition[1]} {condition[2]}")
                    partial_cfs.append(local_cf)
                else:
                    unsatisfied.append(f"{condition[0]} {condition[1]} {condition[2]}")

            all_satisfied = len(unsatisfied) == 0
            partial_cf = CertaintyFactor.combine_multiple(partial_cfs) if partial_cfs else 0.0

            required_conditions.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "confirmed": all_satisfied,
                "satisfied_conditions": satisfied,
                "unsatisfied_conditions": unsatisfied,
                "partial_certainty": round(partial_cf, 4),
                "final_cf": round(CertaintyFactor.combine(partial_cf, rule["cf"]), 4) if all_satisfied else None,
                "mitigation": rule["mitigation"]
            })

        return {
            "goal": goal_threat,
            "found": any(r["confirmed"] for r in required_conditions),
            "rules_checked": required_conditions,
            "message": "Goal confirmed!" if any(r["confirmed"] for r in required_conditions)
                       else "Goal not fully confirmed - missing conditions."
        }

    def unify(self, pattern1, pattern2):
        """
        Unification: Match two logical patterns and find bindings.
        Variables start with '?' (e.g., ?X).
        """
        bindings = {}

        def unify_terms(t1, t2, bindings):
            if t1 == t2:
                return bindings
            if isinstance(t1, str) and t1.startswith('?'):
                return {**bindings, t1: t2}
            if isinstance(t2, str) and t2.startswith('?'):
                return {**bindings, t2: t1}
            if isinstance(t1, (list, tuple)) and isinstance(t2, (list, tuple)):
                if len(t1) != len(t2):
                    return None
                for a, b in zip(t1, t2):
                    bindings = unify_terms(a, b, bindings)
                    if bindings is None:
                        return None
                return bindings
            return None

        result = unify_terms(pattern1, pattern2, bindings)
        return result if result is not None else {}


class CSPSolver:
    """
    MODULE 5: Constraint Satisfaction Problem Solver for Security Planning.
    Goal: Select 5 security measures satisfying all constraints.
    """

    SECURITY_MEASURES = [
        {"id": "M1", "name": "Antivirus Software", "type": "Detective", "categories": ["Malware", "Ransomware", "Trojan"]},
        {"id": "M2", "name": "Email Filtering", "type": "Preventive", "categories": ["Phishing", "SpearPhishing"]},
        {"id": "M3", "name": "Multi-Factor Authentication", "type": "Preventive", "categories": ["BruteForce", "Phishing"]},
        {"id": "M4", "name": "Web Application Firewall", "type": "Preventive", "categories": ["SQLInjection", "XSS"]},
        {"id": "M5", "name": "Intrusion Detection System", "type": "Detective", "categories": ["DDoS", "BruteForce", "Malware"]},
        {"id": "M6", "name": "Regular Backups", "type": "Recovery", "categories": ["Ransomware", "DataLoss"]},
        {"id": "M7", "name": "Patch Management", "type": "Preventive", "categories": ["ZeroDay", "Malware", "Ransomware"]},
        {"id": "M8", "name": "Security Awareness Training", "type": "Preventive", "categories": ["Phishing", "SpearPhishing"]},
        {"id": "M9", "name": "Data Encryption", "type": "Preventive", "categories": ["MITM", "DataExfiltration"]},
        {"id": "M10", "name": "Firewall Rules", "type": "Preventive", "categories": ["DDoS", "BruteForce"]},
    ]

    def __init__(self):
        self.solutions = []

    def _check_constraints(self, selected):
        """Check all CSP constraints on a candidate solution."""
        if len(selected) < 5:
            return False, "Not enough measures selected"

        types = [m["type"] for m in selected]
        all_categories = set()
        for m in selected:
            all_categories.update(m["categories"])

        malware_protection = sum(
            1 for m in selected
            if any(c in m["categories"] for c in ["Malware", "Ransomware", "Trojan"])
        )

        unique_types = len(set(types))
        covers_threat_categories = len(all_categories)
        names = [m["name"] for m in selected]

        violations = []
        if malware_protection < 2:
            violations.append(f"Need ≥2 malware protections (have {malware_protection})")
        if unique_types < 2:
            violations.append(f"Need ≥2 different mitigation types (have {unique_types})")
        if len(names) != len(set(names)):
            violations.append("Duplicate measures found")
        if covers_threat_categories < 2:
            violations.append(f"Must cover ≥2 threat categories (covers {covers_threat_categories})")

        return len(violations) == 0, violations

    def _mrv_heuristic(self, remaining, selected_names):
        """Minimum Remaining Values: Choose variable with fewest legal values."""
        candidates = [m for m in remaining if m["name"] not in selected_names]
        # Sort by number of categories (fewest first - most constrained)
        return sorted(candidates, key=lambda x: len(x["categories"]))

    def solve(self, max_solutions=3):
        """Backtracking CSP solver with MRV heuristic and forward checking."""
        self.solutions = []

        def backtrack(selected, remaining_indices):
            if len(selected) == 5:
                valid, violations = self._check_constraints(selected)
                if valid and len(self.solutions) < max_solutions:
                    selected_names = [m["name"] for m in selected]
                    all_cats = set()
                    for m in selected:
                        all_cats.update(m["categories"])
                    self.solutions.append({
                        "measures": selected.copy(),
                        "types": list(set(m["type"] for m in selected)),
                        "categories_covered": list(all_cats),
                        "solution_id": len(self.solutions) + 1
                    })
                return

            if len(self.solutions) >= max_solutions:
                return

            # Apply MRV heuristic
            candidates = [self.SECURITY_MEASURES[i] for i in remaining_indices]
            ordered = self._mrv_heuristic(candidates, [m["name"] for m in selected])

            for measure in ordered:
                idx = next(i for i, m in enumerate(self.SECURITY_MEASURES) if m["id"] == measure["id"])
                new_remaining = [i for i in remaining_indices if i != idx]

                # Forward checking: prune if impossible to satisfy constraints
                selected.append(measure)
                remaining_count = 5 - len(selected)
                can_satisfy = True

                if remaining_count == 0:
                    valid, _ = self._check_constraints(selected)
                    can_satisfy = valid

                if can_satisfy:
                    backtrack(selected, new_remaining)

                selected.pop()

        all_indices = list(range(len(self.SECURITY_MEASURES)))
        backtrack([], all_indices)
        return self.solutions