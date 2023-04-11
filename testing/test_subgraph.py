import networkx as nx

# create a graph
G = nx.Graph()

# add nodes to the graph
G.add_nodes_from([1, 2, 3, 4, 5, 6, 7, 8])

# add edges to the graph
G.add_edges_from([(1, 2), (1, 3), (2, 3), (4, 5), (5, 6), (3, 7), (7, 8)])

# create a subset of nodes
subset = [1, 2, 8, 3, 7]

# extract the subgraph
subgraph = G.subgraph(subset)

# print the nodes and edges in the subgraph
print("Nodes in subgraph:", subgraph.nodes())
print("Edges in subgraph:", subgraph.edges())
