import os.path
from copy import deepcopy

import networkx as nx

from utils.string_utils import insert_string

color_mapping = {
    '0': 'red',
    '1': 'blue',
    '2': 'skyblue',
    '3': 'seagreen',
    '4': 'purple',
    '5': 'olivedrab1',
    '6': 'lawngreen',
    '7': 'navy',
    '8': 'yellowgreen',
    '9': 'tan2',
    '10': 'pink',
    '11': 'orange',
    '12': 'peru',
    '13': 'turquoise',
    '14': 'grey'
}


def get_node_information(s):
    if not s.startswith('a0x'):
        address = s.upper()
        opcode = s.upper()
        opcode = "-".join(opcode.split("_"))
        return address, opcode
    address = s[1:11]
    opcode = s[11:]

    return address, opcode


def relabel_graph(G, label_with_address=False, using_opcode_params=False):
    def get_opcode_params(label_of_node, opcode):
        label_of_node = label_of_node.split(" ")[1:]
        new_label = opcode
        for param_of_node in label_of_node:
            if "%" in param_of_node:
                new_label += "_reg"
            else:
                new_label += "_val"
        return new_label

    attribution_mapping = {}
    label_mapping = {}
    for node in G.nodes:
        address, opcode = get_node_information(node)
        if not label_with_address:
            if not using_opcode_params:
                attribution_mapping[address] = {"label": opcode.split("_")[0]}
            else:
                new_label = get_opcode_params(G.nodes[node]["label"], opcode.split("_")[0])
                attribution_mapping[address] = {"label": new_label}
        else:
            if not using_opcode_params:
                attribution_mapping[address] = {"label": address + '\n' + opcode.split("_")[0]}
            else:
                new_label = get_opcode_params(G.nodes[node]["label"], opcode.split("_")[0])
                attribution_mapping[address] = {"label": address + '\n' + new_label}

        label_mapping[node] = address
    nG = nx.relabel_nodes(G, label_mapping)
    nx.set_node_attributes(nG, attribution_mapping)
    return nG


def remove_back_edge(cfg):
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


def get_sub_graph_from(G, node):
    def dfs(start_node):
        stack = []
        visited = []
        stack.append(start_node)
        while len(stack) > 0:
            u = stack[-1]
            visited.append(u)
            exist_node = False
            for v in list(G.predecessors(u)):
                if not (v in visited):
                    exist_node = True
                    stack.append(v)
                    break
            if not exist_node:
                stack.pop()
        return visited

    subset_of_node = dfs(node)
    return G.subgraph(subset_of_node)


def color_graph(G, obfuscation_tech_sequence, obfuscation_address_sequence, name_dot_file):
    tech_seq = obfuscation_tech_sequence.split("_")
    add_seq = obfuscation_address_sequence.split("_")
    for idx, address in enumerate(add_seq):
        address = insert_string(address, "00", 2)
        if len(address) != 10:
            continue
        for node in G.nodes:
            # print("node: {}, add: {}".format(node, address))
            if address in node:
                # print("pass")
                # print(tech_seq[idx])
                if tech_seq[idx] in color_mapping:
                    G.nodes[node]["color"] = color_mapping[tech_seq[idx]].strip()
                    G.nodes[node]['fillcolor'] = color_mapping[tech_seq[idx]].strip()
    nx.nx_agraph.write_dot(G, os.path.join("logs/log_graph_color", "colored_{}".format(name_dot_file)))
    # import re
    #
    # # read in the DOT file
    # with open(os.path.join("logs/log_graph_color", "colored_{}".format(name_dot_file)), 'r') as f:
    #     dot_data = f.read()
    #
    # # remove the escape characters from the attribute values
    # dot_data = re.sub(r'\\(.)', r'\1', dot_data)
    # dot_data = re.sub(r'\\', '', dot_data)
    # # save the modified DOT file
    # with open(os.path.join("logs/log_graph_color", "colored_{}".format(name_dot_file)), 'w') as f:
    #     f.write(dot_data)

# def get_node_information(s):
#     if not s.startswith('a0x'):
#         address = s
#         opcode = "API"
#         return address, opcode
#     address = s[1:11]
#     opcode = s[11:]
#
#     return address, opcode
