"""
MODULE 3: Search Algorithms on Cyber Security Knowledge Graph
Implements BFS, DFS, and A* for threat traversal and recommendation.
Optimized to work with RDF-based URI structures.
"""

from collections import deque
import heapq

class ThreatGraphSearch:
    """
    Search algorithms operating on the Graph Dictionary
    generated from the CyberSecKnowledgeGraph.
    """

    def __init__(self, graph_data):
        """
        graph_data: dict of {uri: {label, type, severity, ip, vuln, related: [...]}}
        """
        self.graph = graph_data or {}

    def bfs_threats_from_ip(self, target_ip):
        """
        BFS: Find ALL threats connected to a given IP address.
        Useful for identifying the scope of an attack from a specific source.
        """
        if not target_ip: return []
        
        visited = set()
        queue = deque()
        result = []

        # Find starting nodes: any threat in the graph originating from this IP
        for uri, data in self.graph.items():
            if data.get('ip') == target_ip:
                queue.append((uri, 0)) # (URI, distance)
                visited.add(uri)

        while queue:
            current_uri, level = queue.popleft()
            node = self.graph.get(current_uri, {})
            
            result.append({
                'uri': current_uri,
                'label': node.get('label', 'Unknown'),
                'type': node.get('type', 'Threat'),
                'severity': node.get('severity', 0),
                'ip': node.get('ip', ''),
                'level': level
            })

            # Traverse neighbors via cs:relatedTo links
            for neighbor in node.get('related', []):
                if neighbor not in visited and neighbor in self.graph:
                    visited.add(neighbor)
                    queue.append((neighbor, level + 1))

        return result

    def dfs_attack_chain(self, start_uri, max_depth=5):
        """
        DFS: Explore the deep "Attack Chain" of connected threats.
        Useful for uncovering multi-stage persistent threats.
        """
        if start_uri not in self.graph: return []
        
        visited = set()
        chain = []

        def explore(uri, depth):
            if depth > max_depth or uri in visited or uri not in self.graph:
                return
            
            visited.add(uri)
            node = self.graph[uri]
            chain.append({
                'uri': uri,
                'label': node.get('label', 'Unknown'),
                'type': node.get('type', 'Threat'),
                'depth': depth,
                'severity': node.get('severity', 0)
            })
            
            for neighbor in node.get('related', []):
                explore(neighbor, depth + 1)

        explore(start_uri, 0)
        return chain

    def astar_similar_threats(self, query_uri, top_k=5):
        """
        A*: Recommends threats based on a similarity heuristic.
        Cost (f) = g (distance in graph) + h (attribute mismatch).
        """
        top_k = int(top_k) 
        query_node = self.graph.get(query_uri)
        if not query_node: return []

        # Priority Queue for A* search: (f_score, uri)
        pq = []
        
        for uri, node in self.graph.items():
            if uri == query_uri: continue
            
            # Heuristic: Calculate "distance" in attributes
            h = self._heuristic(query_node, node)
            heapq.heappush(pq, (h, uri))

        recommendations = []
        while pq and len(recommendations) < top_k:
            cost, uri = heapq.heappop(pq)
            node = self.graph[uri]
            
            # Convert cost to a 0-1 Similarity Score
            similarity = round(max(0.1, 1 - (cost / 3.0)), 2)
            
            recommendations.append({
                'uri': uri,
                'label': node.get('label', 'Unknown'),
                'type': node.get('type', 'Threat'),
                'severity': node.get('severity', 0),
                'similarity_score': similarity,
                'ip': node.get('ip', ''),
                'vuln': node.get('vuln', '')
            })
            
        return recommendations

    def _heuristic(self, query, candidate):
        """
        Computes the 'Difference Cost' between two threats.
        Lower score = Higher similarity.
        """
        cost = 0.0
        
        # 1. Type mismatch (Weight: 1.0)
        if query.get('type') != candidate.get('type'):
            cost += 1.0
            
        # 2. Vulnerability mismatch (Weight: 1.0)
        if query.get('vuln') != candidate.get('vuln'):
            cost += 1.0
            
        # 3. IP Subnet mismatch (Weight: 1.0)
        q_ip = str(query.get('ip', '')).split('.')
        c_ip = str(candidate.get('ip', '')).split('.')
        
        # If IPs exist and match first two octets (same network), cost is lower
        if len(q_ip) >= 2 and len(c_ip) >= 2:
            if q_ip[:2] != c_ip[:2]:
                cost += 1.0
        else:
            cost += 1.0

        return cost