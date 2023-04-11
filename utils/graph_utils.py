from copy import deepcopy

import networkx as nx


def get_node_information(s):
    if not s.startswith('a0x'):
        address = s
        opcode = "API"
        return address, opcode
    address = s[1:11]
    opcode = s[11:]

    return address, opcode


def relabel_graph(G):
    attribution_mapping = {}
    label_mapping = {}
    for node in G.nodes:
        address, opcode = get_node_information(node)
        attribution_mapping[address] = {"opcode": opcode}
        label_mapping[node] = address
    nG = nx.relabel_nodes(G, label_mapping)
    nx.set_node_attributes(nG, attribution_mapping)
    print(attribution_mapping)
    return nG


def remove_back_edege(cfg):
    new_cfg = deepcopy(cfg)
    visited = []

    start_node = list(cfg.nodes)[0]
    degrees = {}

    def bfs(start_node):
        index = 0
        visited.append(start_node)
        degrees[start_node] = 1
        new_cfg.nodes[start_node]["degree"] = 1
        while index < len(visited):
            u = visited[index]
            degree = degrees[u]
            for v in list(new_cfg.successors(u)):
                if not (v in visited):
                    visited.append(v)
                    degrees[v] = degree + 1
                    new_cfg.nodes[v]["degree"] = degree + 1
                else:
                    new_cfg.remove_edge(u, v)
            index += 1

    def dfs(start_node):
        stack = []
        visited = []
        stack.append(start_node)
        while len(stack) > 0:
            u = stack[-1]
            visited.append(u)
            exist_node = False
            for v in list(new_cfg.successors(u)):
                if not (v in visited):
                    exist_node = True
                    stack.append(v)
                    break
                else:
                    if v in stack:
                        new_cfg.remove_edge(u, v)
            if not exist_node:
                stack.pop()

    dfs(start_node)
    return new_cfg
