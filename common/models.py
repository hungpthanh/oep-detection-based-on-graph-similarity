import time
from copy import deepcopy

import networkx as nx
from matplotlib import pyplot as plt
from networkx.drawing.nx_agraph import read_dot

from utils.graph_utils import relabel_graph


class CFG():
    def __init__(self, dot_file):
        self.nx_graph = relabel_graph(nx.DiGraph(read_dot(path=dot_file)))
        self.nodes = []
        self.start_node = None
        self.adj = {}
        self.rev_adj = {}

        for idx, node in enumerate(self.nx_graph.nodes):
            print(self.nx_graph.nodes[node]['opcode'])
            self.nodes.append(node)
            if idx == 0:
                self.start_node = node

        for idx, edge in enumerate(self.nx_graph.edges):
            source, target = edge
            # crate adj list
            if not (target in self.adj[source]):
                self.adj[source].append(target)
            # crate rev adj list
            if not (source in self.rev_adj[target]):
                self.rev_adj[target].append(source)

    def reset(self):
        self.nx_graph = nx.DiGraph()
        self.nodes = []
        self.start_node = None
        self.adj = {}
        self.rev_adj = {}

    def add_node(self, address, opcode):
        if not (address in self.nodes):
            self.nx_graph.add_node(address, opcode=opcode)
            self.nodes.append(address)

    def get_node_attribute(self, address):
        return self.nx_graph.nodes[address]

    def add_edge(self, address1, opcode1, address2, opcode2):
        if not (self.nx_graph.has_edge(address1, address2)):
            if not self.nx_graph.has_node(address1):
                self.add_node(address1, opcode1)
            if not self.nx_graph.has_node(address2):
                self.add_node(address2, opcode2)
            self.nx_graph.add_edge(address1, address2)
            self.adj[address1].append(address2)
            self.rev_adj[address2].append(address1)





if __name__ == '__main__':
    cfg = relabel_graph(nx.DiGraph(read_dot(path="data/asm_cfg/upx/upx_accesschk.exe_model.dot")))
    new_cfg = remove_back_edege(cfg)
    print(new_cfg.nodes)
    nx.nx_agraph.write_dot(new_cfg, "my_graph.dot")
