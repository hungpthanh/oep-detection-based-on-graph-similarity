import os.path
from copy import deepcopy

import networkx as nx
import sys

from networkx.drawing.nx_agraph import read_dot

sys.path.append('.')
# from common.models import create_subgraph
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

data_folder_path = "data"


def load_end_unpacking_sequence():
    end_unpacking_sequences = {}
    with open("configs/end_of_unpacking_sequence.txt", "r") as f:
        for line in f:
            packer_name, sequence = line.split(",")
            if not packer_name in end_unpacking_sequences:
                end_unpacking_sequences[packer_name] = []
            end_unpacking_sequences[packer_name].append(sequence.strip().split("_"))
    return end_unpacking_sequences


end_unpacking_sequence_samples = load_end_unpacking_sequence()


def get_node_information(s):
    if not s.startswith('a0x'):
        address = s.upper()
        opcode = s.upper()
        opcode = "-".join(opcode.split("_"))
        return address, opcode
    address = s[1:11]
    opcode = s[11:]

    return address, opcode


def relabel_graph(G, label_with_address=False):
    attribution_mapping = {}
    label_mapping = {}
    for node in G.nodes:
        address, opcode = get_node_information(node)
        nNode = address if not node.startswith('a0x') else node
        if not label_with_address:
            attribution_mapping[nNode] = {"label": opcode.split("_")[0]}
        else:
            attribution_mapping[nNode] = {"label": address + '\n' + opcode.split("_")[0]}
        if not node.startswith('a0x'):
            # print("update API: {}".format(node))
            label_mapping[node] = node.upper()
        # else:
        #     label_mapping[node] = node
    nG = nx.relabel_nodes(G, label_mapping)  # keep orginal node identity
    nx.set_node_attributes(nG, attribution_mapping)
    # nx.set_node_attributes(G, attribution_mapping)
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


def get_sub_graph_from(G, node, from_bottom=True, depth=-1):
    def dfs(start_node, from_bottom):
        stack = []
        visited = []
        stack.append(start_node)
        while len(stack) > 0:
            u = stack[-1]
            visited.append(u)

            if len(stack) == depth:
                stack.pop()
                continue

            exist_node = False
            next_nodes = G.predecessors(u) if from_bottom else G.successors(u)
            for v in list(next_nodes):
                if not (v in visited):
                    exist_node = True
                    stack.append(v)
                    break
            if not exist_node:
                stack.pop()
        return visited

    subset_of_node = dfs(node, from_bottom)
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

def get_opcode_sequence(G, node):
    predecessor = [pre_node for pre_node in G.predecessors(node)]
    sequences = []
    while len(predecessor) == 1:
        sequences.append(G.nodes[node]["label"])
        node = predecessor[0]
        predecessor = [pre_node for pre_node in G.predecessors(node)]
    sequences.append(G.nodes[node]["label"])
    return sequences


# def is_graph_matching_end_unpacking_sequence(packer_name, file_name, address, first_k=-1):
#     if first_k == -1:
#         return True
#     sample_file_path = os.path.join(data_folder_path, "asm_cfg", packer_name,
#                                     "{}_{}_model.dot".format(packer_name, file_name))
#     import time
#     start_time = time.time()
#     G1 = create_subgraph(dot_file=os.path.join(sample_file_path),
#                          address=address, from_specific_node=True)
#     print("Create subgraph time: {}".format(time.time() - start_time))
#     # print("seq seq: {}".format(get_opcode_sequence(G1, address)))
#     seq = get_opcode_sequence(G1, address)
#     # print(seq)
#     for end_unpacking_seq in end_unpacking_sequences[packer_name]:
#         print("seq: {}, end-unpackig: {}, res: {}".format(seq[:first_k], end_unpacking_seq[:first_k], seq[:first_k] == end_unpacking_seq[:first_k]))
#         if seq[:first_k] == end_unpacking_seq[:first_k]:
#             return True
#     return False


def create_subgraph(removed_back_edge_G, address, from_specific_node=True, from_bottom=True, depth=-1):
    if from_specific_node:
        G = get_sub_graph_from(removed_back_edge_G, address, from_bottom, depth)
        return G
    return removed_back_edge_G


def get_removed_backed_graph(packer_name, file_name, label_with_address=False):
    file_path = os.path.join(data_folder_path, "asm_cfg", packer_name,
                             "{}_{}_model.dot".format(packer_name, file_name))
    G = relabel_graph(nx.DiGraph(read_dot(path=file_path)), label_with_address)
    G = remove_back_edge(G)
    return G


def verify_cfg(dot_file):
    if not os.path.exists(dot_file):
        return False, "Dot file not exist"
    try:
        cfg = nx.DiGraph(read_dot(path=dot_file))
    except Exception as e:
        return False, str(e)
    return True, "Success"
