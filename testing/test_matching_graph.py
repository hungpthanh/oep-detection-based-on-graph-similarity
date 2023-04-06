import networkx as nx

# create two directed graphs
G1 = nx.DiGraph()
G1.add_node(1, label='A')
G1.add_node(2, label='B')
G1.add_edge(1, 2)

G2 = nx.DiGraph()
G2.add_node('A', color='red')
G2.add_node('B', color='blue')
G2.add_edge('A', 'B')

# create a DiGraphMatcher object with node_match function that compares 'label' attribute
matcher = nx.algorithms.isomorphism.DiGraphMatcher(G1, G2, node_match=lambda n1, n2: n1['label'] == n2['color'])

# check semantic feasibility of matching node 1 in G1 with node 'A' in G2
print(matcher.semantic_feasibility(1, 'A'))  # prints True

# check semantic feasibility of matching node 2 in G1 with node 'A' in G2
print(matcher.semantic_feasibility(2, 'A'))  # prints False
