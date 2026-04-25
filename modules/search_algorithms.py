"""
MODULE 3: Search Algorithms on Cyber Security Knowledge Graph
Implements BFS, DFS, and A* for threat traversal and recommendation.
"""

from collections import deque
import heapq


class ThreatGraphSearch:
    """
    Search algorithms operating on the RDF knowledge graph
    represented as an adjacency structure.
    """

    def __init__(self, graph_data):
        """
        graph_data: dict of {node_uri: {label, type, severity, ip, vuln, related: [...]}}
        """
        self.graph = graph_data

    def bfs_threats_from_ip(self, target_ip):
        """
        BFS: Find ALL threats connected to a given IP address.
        Returns list of threat nodes in BFS order.
        """
        visited = set()
        queue = deque()
        result = []

        # Find starting nodes (threats that originate from this IP)
        start_nodes = [
            uri for uri, data in self.graph.items()
            if data.get('ip') == target_ip
        ]

        if not start_nodes:
            return []

        for start in start_nodes:
            queue.append(start)
            visited.add(start)

        while queue:
            current = queue.popleft()
            node_data = self.graph.get(current, {})
            result.append({
                'uri': current,
                'label': node_data.get('label', current),
                'type': node_data.get('type', 'Unknown'),
                'severity': node_data.get('severity', 0),
                'ip': node_data.get('ip', ''),
                'level': node_data.get('level', 0)
            })

            # Traverse related threats
            for related_uri in node_data.get('related', []):
                if related_uri not in visited:
                    visited.add(related_uri)
                    queue.append(related_uri)

        return result

    def dfs_attack_chain(self, start_uri, max_depth=6):
        """
        DFS: Explore full attack chain from a given threat node.
        Returns the complete chain of connected threats.
        """
        visited = set()
        chain = []

        def dfs_recursive(uri, depth):
            if depth > max_depth or uri in visited:
                return
            visited.add(uri)
            node_data = self.graph.get(uri, {})
            chain.append({
                'uri': uri,
                'label': node_data.get('label', uri),
                'type': node_data.get('type', 'Unknown'),
                'severity': node_data.get('severity', 0),
                'depth': depth,
                'ip': node_data.get('ip', ''),
                'vuln': node_data.get('vuln', '')
            })
            for related_uri in node_data.get('related', []):
                dfs_recursive(related_uri, depth + 1)

        dfs_recursive(start_uri, 0)
        return chain

    def astar_similar_threats(self, query_threat_uri, top_k=5):
        """
        A*: Recommend similar threats using heuristic based on:
        - Attack type similarity
        - Vulnerability similarity
        - Source IP similarity
        Lower cost = more similar threat.
        """
        query_data = self.graph.get(query_threat_uri, {})
        if not query_data:
            return []

        # Priority queue: (f_score, uri)
        open_set = []
        g_score = {query_threat_uri: 0}

        # Initialize with all threats as candidates
        for uri, data in self.graph.items():
            if uri != query_threat_uri:
                h = self._heuristic(query_data, data)
                heapq.heappush(open_set, (h, uri))

        results = []
        visited = set()

        while open_set and len(results) < top_k:
            f, uri = heapq.heappop(open_set)
            if uri in visited:
                continue
            visited.add(uri)

            node_data = self.graph.get(uri, {})
            similarity = round(max(0, 1 - f / 3.0), 3)  # Normalize to 0-1

            results.append({
                'uri': uri,
                'label': node_data.get('label', uri),
                'type': node_data.get('type', 'Unknown'),
                'severity': node_data.get('severity', 0),
                'similarity_score': similarity,
                'heuristic_cost': round(f, 3),
                'ip': node_data.get('ip', ''),
                'vuln': node_data.get('vuln', '')
            })

        return results

    def _heuristic(self, query, candidate):
        """
        Heuristic function for A*:
        Computes distance between two threats based on:
        1. Type mismatch (0 = same, 1 = different)
        2. Vulnerability mismatch (0 = same, 1 = different)
        3. IP similarity (0 = same subnet, 1 = different subnet)
        """
        cost = 0.0

        # Type similarity (weight: 1.0)
        if query.get('type') != candidate.get('type'):
            cost += 1.0

        # Vulnerability similarity (weight: 1.0)
        if query.get('vuln') != candidate.get('vuln'):
            cost += 1.0

        # IP similarity (weight: 1.0)
        q_ip = query.get('ip', '').split('.')
        c_ip = candidate.get('ip', '').split('.')
        if len(q_ip) == 4 and len(c_ip) == 4:
            # Compare first two octets (same subnet = similar)
            if q_ip[:2] != c_ip[:2]:
                cost += 1.0
        else:
            cost += 1.0

        return cost