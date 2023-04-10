import networkx as nx

# create a directed graph
G = nx.DiGraph()

# add nodes and edges
G.add_edge(1, 2)
G.add_edge(3, 2)
G.add_edge(4, 2)

# get incoming nodes of node 2
incoming_nodes = list(G.predecessors(2))

# print the incoming nodes
print(incoming_nodes)
