import os

import networkx as nx
from networkx.drawing.nx_agraph import read_dot

G = nx.DiGraph(read_dot(path="packed_dot_file"))
nx.nx_agraph.write_dot(G, os.path.join("logs/log_graph_color", "colored_{}".format("abc")))