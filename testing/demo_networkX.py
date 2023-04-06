import os.path

import networkx as nx
from networkx.drawing.nx_agraph import write_dot, read_dot

from utils.oep_utils import get_oep_dataset
from utils.preprocess_be_pum import update_information_FSG
from utils.pygraphviz_demmo import get_node_information

oep_dictionary = get_oep_dataset()
packed_list_path = "data/packed_files_FSG.txt"
asm_cfg_path = "data/asm_cfg"

information = update_information_FSG(packed_list_path)

with open(packed_list_path, "r") as f:
    packed_file = [line.strip() for line in f]

G = {}
paths = {}


def relabel_graph(G):
    attribution_mapping = {}
    label_mapping = {}
    for node in G.nodes:
        address, opcode = get_node_information(node)
        attribution_mapping[address] = {"opcode": opcode}
        label_mapping[node] = address
    nG = nx.relabel_nodes(G, label_mapping)
    nx.set_node_attributes(nG, attribution_mapping)
    return nG


for name in packed_file:
    if not (name in information):
        continue
    # print(name)
    # print(information[name])
    if not ("end_unpacking" in information[name]):
        continue
    if not ("previous_OEP" in information[name]):
        continue
    G[name] = nx.DiGraph(read_dot(path=os.path.join(asm_cfg_path, name + "_model.dot")))
    G[name] = relabel_graph(G[name])

    print("name = {}".format(name))
    source = list(G[name].nodes)[0]
    target = information[name]["previous_OEP"]
    paths[name] = list(nx.shortest_simple_paths(G[name], source, target))
    for path in paths[name]:
        print(path)