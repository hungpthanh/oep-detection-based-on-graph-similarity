import time

import networkx as nx
import pygraphviz as pgv
from networkx.drawing.nx_agraph import read_dot

from utils.graph_utils import relabel_graph, get_node_information

visited = []
name_file = "outputs/fsg_Cacheset.exe_model.dot"
name_file = "outputs/fsg_accesschk.exe_model.dot"
name_file = "outputs/upx_accesschk.exe_model.dot"
name_file = "outputs/packed_unikey32.exe_model.dot"
name_file = "outputs/packed_Cacheset.exe_model.dot"
G = pgv.AGraph("/home/hungpt/workspace/research/oep-detection/utils/{}".format(name_file))

# print(G.nodes())
# print(G.edges())
# print(len(G.nodes()))
# print(len(G.edges()))


adj = {}
label = {}




# start_node = -1
#
# for idx, node in enumerate(G.nodes()):
#     address, opcode = get_node_information(node)
#     if not address in adj:
#         adj[address] = []
#         label[address] = opcode
#     if idx == 0:
#         start_node = address
#
# for edge in G.edges():
#     source, target = edge
#     source, target = get_node_information(source), get_node_information(target)
#     if not (target[0] in adj[source[0]]):
#         adj[source[0]].append(target[0])
#
# for key, value in adj.items():
#     # value.sort(key=compare)
#     value = sorted(value, key=lambda x: label[x])


class BPCFG():
    def __init__(self, dot_file):
        self.G = pgv.AGraph(dot_file)
        self.start_node = -1
        self.adj = {}
        self.rev_adj = {}
        self.label = {}
        self.bfs_order = []
        for idx, node in enumerate(self.G.nodes()):
            address, opcode = get_node_information(node)
            if not address in self.adj:
                self.adj[address] = []
                self.rev_adj[address] = []
                self.label[address] = opcode
            if idx == 0:
                self.start_node = address

        for edge in self.G.edges():
            source, target = edge
            source, target = get_node_information(source), get_node_information(target)
            if not (target[0] in self.adj[source[0]]):
                self.adj[source[0]].append(target[0])
            if not (source[0] in self.rev_adj[target[0]]):
                self.rev_adj[target[0]].append(source[0])

    def get_incoming_node(self, node_address):
        results = []
        for key, value in self.adj.items():
            if node_address in value:
                results.append(key)
        return results

    def get_bfs_order(self):
        if len(self.bfs_order) != 0:
            return self.bfs_order
        self.bfs_order.append(self.start_node)
        cnt = 0
        while cnt < len(self.bfs_order):
            current_address = self.bfs_order[cnt]

    def get_rev_path_from(self, address):
        results = []
        path = [address]

        def dfs(u):
            if u == self.start_node:
                results.append(path.copy())
                return
            for v in self.rev_adj[u]:
                if not (v in path):
                    path.append(v)
                    dfs(v)
                    path.remove(v)

        dfs(address)
        return results

    def clear_cycle(self):
        visited = []

        def dfs(u):
            visited.append(u)
            for v in self.adj[u]:
                if v in visited:
                    self.adj[u].remove(v)
                    self.rev_adj[v].remove(u)
                else:
                    dfs(v)

        dfs(self.start_node)
