import networkx as nx
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



if __name__ == '__main__':
    cfg = CFG(dot_file="data/asm_cfg/upx/upx_accesschk.exe_model.dot")
