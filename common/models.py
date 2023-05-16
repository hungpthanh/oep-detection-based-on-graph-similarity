from utils.graph_utils import remove_back_edge, get_sub_graph_from, get_node_information
import networkx as nx
import pygraphviz as pgv
from networkx.drawing.nx_agraph import read_dot
from utils.graph_utils import relabel_graph


# def get_node_information(s):
#     if not s.startswith('a0x'):
#         address = s
#         opcode = "API"
#         return address, opcode
#     address = s[1:11]
#     opcode = s[11:]
#
#     return address, opcode


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

            # print("st: {} {}".format(source, target))
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

    def get_rev_path_from(self, address):
        results = []
        path = [address]

        def dfs(u):
            # print("u = {}".format(u))
            # time.sleep(0.5)
            if u == self.start_node:
                results.append(path.copy())
                print(path.copy())
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
            # if u == self.start_node:
            #     results.append(path.copy())
            #     print(path.copy())
            #     return
            for v in self.adj[u]:
                if v in visited:
                    self.adj[u].remove(v)
                    self.rev_adj[v].remove(u)
                else:
                    dfs(v)

        dfs(self.start_node)


def create_subgraph(dot_file, address, from_specific_node=True, label_with_address=False):
    G = relabel_graph(nx.DiGraph(read_dot(path=dot_file)), label_with_address)
    G = remove_back_edge(G)
    if from_specific_node:
        G = get_sub_graph_from(G, address)
        return G
    return G


if __name__ == '__main__':
    cfg = relabel_graph(nx.DiGraph(read_dot(path="data/asm_cfg/upx/upx_AccessEnum.exe_model.dot")))
    new_cfg = remove_back_edge(cfg)
    subgraph = get_sub_graph_from(new_cfg, "0x00407a98")
    nx.nx_agraph.write_dot(subgraph, "my_graph_upx_AccessEnum.dot")
