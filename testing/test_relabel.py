import networkx as nx

# Create a directed graph
G = nx.DiGraph()
G.add_edges_from([(1, "a0x004c4981movl_0x495000UINT32_esi"), (1, "GatProcAddress_kernel32_dlllllllllllll"), (1, "GetProcAddress_kernel32_dlllllllllllll")])

for v in G.successors(1):
    print(v)
# Create a mapping dictionary
mapping = {2: 'A', 3: 'A'}

# Relabel nodes using the mapping dictionary
H = nx.relabel_nodes(G, mapping)

print(H.edges())
