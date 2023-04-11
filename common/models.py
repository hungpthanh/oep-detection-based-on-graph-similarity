import time
from copy import deepcopy
from node2vec import Node2Vec

import networkx as nx
import numpy as np
from matplotlib import pyplot as plt
from networkx.drawing.nx_agraph import read_dot
from numpy.linalg import norm
from sklearn.metrics import pairwise_kernels
from sklearn.preprocessing import MinMaxScaler
import torch
import torch.nn as nn
import torch.nn.functional as F
from utils.graph_utils import relabel_graph, remove_back_edge, get_sub_graph_from
from grakel import GraphKernel, graph_from_networkx, WeisfeilerLehman, VertexHistogram
import time

import networkx as nx
import pygraphviz as pgv
from networkx.drawing.nx_agraph import read_dot

from utils.graph_utils import relabel_graph


def get_node_information(s):
    if not s.startswith('a0x'):
        address = s
        opcode = "API"
        return address, opcode
    address = s[1:11]
    opcode = s[11:]

    return address, opcode


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


def wl_kernel(G, iterations):
    labels = list(nx.get_node_attributes(G, 'opcode'))
    labels = [label.split('_')[0] for label in labels]

    labels = [G.nodes[node]["opcode"] for node in G.nodes]
    labels = {}
    # for node in G.nodes:
    #     labels[]
    # print(labels)
    for i in range(iterations):
        labels_new = {}
        for node in G.nodes():
            neighbors = G.neighbors(node)
            # print("neightbor : {}".format(neighbors))
            # for n in neighbors:
            #     print(n)
            neighbor_labels = tuple(sorted([G.nodes[n]["opcode"].split("_")[0] for n in neighbors]))
            label = (G.nodes[node]["opcode"], neighbor_labels)
            labels_new[node] = label
        labels = labels_new
    label_array = np.array(list(labels.values()))
    print("label array")
    print(label_array)
    unique_labels = np.unique(label_array)
    label_dict = {label: i for i, label in enumerate(unique_labels)}
    feature_vector = np.zeros(len(label_dict))
    for label in label_array:
        feature_vector[label_dict[label]] += 1
    return feature_vector


def create_subgraph(dot_file, address, from_specific_node=True):
    cfg = relabel_graph(nx.DiGraph(read_dot(path=dot_file)))
    new_cfg = remove_back_edge(cfg)
    if from_specific_node:
        subgraph = get_sub_graph_from(new_cfg, address)
        return subgraph
    return new_cfg


if __name__ == '__main__':
    cfg = relabel_graph(nx.DiGraph(read_dot(path="data/asm_cfg/upx/upx_Dbgview.exe_model.dot")))
    new_cfg = remove_back_edge(cfg)
    # print(new_cfg.nodes)
    subgraph = get_sub_graph_from(new_cfg, "0x00415757")
    start_node = list(new_cfg.nodes)[0]
    # print(start_node)
    # for path in nx.all_simple_paths(subgraph, source=start_node, target="0x00415757"):
    #     print(path)
    # nx.nx_agraph.write_dot(new_cfg, "my_graph_upx_Dbgview.dot")
    # nx.nx_agraph.write_dot(subgraph, "sub_graph_upx_Dbgview.dot")

    G1 = nx.DiGraph(read_dot(path="sub_graph.dot"))
    # G2 = nx.DiGraph(read_dot(path="sub_graph.dot"))
    G2 = nx.DiGraph(read_dot(path="sub_graph_upx_Dbgview.dot"))

    G1 = create_subgraph(dot_file="data/asm_cfg/upx/upx_Dbgview.exe_model.dot", address="0x00415757")

    print(nx.get_node_attributes(G1, "opcode"))

    # generate node embeddings using Node2Vec
    node2vec = {}
    model = {}
    embeddings = {}
    node_to_index = {}
    node2vec["G1"] = Node2Vec(G1, dimensions=64, walk_length=60, num_walks=2, seed=23)
    model["G1"] = node2vec["G1"].fit(window=10, min_count=1, workers=4)

    # get the embeddings for all nodes in the graph
    embeddings["G1"] = model["G1"].wv.vectors
    node_to_index["G1"] = model["G1"].wv.key_to_index



    A = embeddings["G1"][node_to_index["G1"]["0x00415757"]]

    max_value = -1
    saveAddress = -1
    node_list = list(create_subgraph(dot_file="data/asm_cfg/upx/upx_accesschk.exe_model.dot", address="-1",
                         from_specific_node=False).nodes)
    for node in node_list:
        # if node != "0x"
        G2 = create_subgraph(dot_file="data/asm_cfg/upx/upx_accesschk.exe_model.dot", address=node,
                             from_specific_node=True)
        node2vec["G2"] = Node2Vec(G2, dimensions=64, walk_length=60, num_walks=2, seed=23)
        model["G2"] = node2vec["G2"].fit(window=10, min_count=1, workers=4)

        # get the embeddings for all nodes in the graph
        embeddings["G2"] = model["G2"].wv.vectors
        node_to_index["G2"] = model["G2"].wv.key_to_index
        B = embeddings["G2"][node_to_index["G2"][node]]
        cosine = np.dot(A, B) / (norm(A) * norm(B))
        if cosine > max_value:
            max_value = cosine
            saveAddress = node
    print("saveAddress = {}".format(saveAddress))
    print("maxvalue = {}".format(max_value))
    # print("Cosine Similarity:", cosine)
