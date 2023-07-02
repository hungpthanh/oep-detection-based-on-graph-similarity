# from utils.preprocess_be_pum import get_OEP_of_UPX
import os
from collections import Counter

import networkx as nx
import pefile
from networkx.drawing.nx_agraph import read_dot

from utils.graph_similarity_utils import convert_graph_to_vector, get_feature_vector, cosine_similarity
# from common.models import BPCFG, create_subgraph
from utils.graph_utils import create_subgraph, get_removed_backed_graph, relabel_graph, remove_back_edge

packed_file_path = "data/packed_files.txt"
packedSignature_path = "data/packerSignature.txt"
positionDetail_path = "data/positionDetail.txt"

# load offset observed
offsets = []
with open("configs/offsets.txt", "r") as f:
    for line in f:
        offsets.append(line.strip())


# def build_OEP_dataset(packed_file_path):
#     information = {}
#     with open(packed_file_path, "r") as f:
#         packed_file = [line.strip() for line in f]
#
#     import csv
#
#     # open the file in the write mode
#     with open('OEP_dataset.csv', 'w') as f:
#         # create the csv writer
#         writer = csv.writer(f)
#
#         fieldnames = ['name', 'OEP']
#         # writer = csv.DictWriter(f, fieldnames=fieldnames)
#         # write a row to the csv file
#         names = []
#         oep_address = []
#         writer.writerow(fieldnames)
#         for name in packed_file:
#             previous_OEP, OEP = get_OEP_of_UPX(name)
#             if OEP is not None:
#                 if not (name in information):
#                     information[name] = {}
#                     names.append(name)
#                     oep_address.append(OEP)
#                     writer.writerow([name, OEP])
#                 information[name]["previous_OEP"] = previous_OEP
#
#                 information[name]["OEP"] = OEP
#
#         # writer.writerow([list_1[w], list_2[w]])


# build_OEP_dataset(packed_file_path)

def get_oep_dataset():
    results = {}
    with open("OEP_dataset.csv", "r") as f:
        for line in f:
            line = line.strip()
            name, oep = line.split(',')
            results[name] = oep
    return results


def get_preceding_oep(file_path, oep_address):
    dot_file = file_path
    if not os.path.exists(dot_file):
        return False, "Dot file not exist"
    try:
        cfg = nx.DiGraph(read_dot(path=dot_file))
        # cfg = BPCFG(dot_file)
    except Exception as e:
        return False, str(e)
    preceding_oep = None
    for node in cfg.nodes:
        if "a" + oep_address in node:
            preceding_oep = [v for v in cfg.predecessors(node)]
    # preceding_oep = cfg.get_incoming_node(oep_address)
    if preceding_oep is None or len(preceding_oep) == 0:
        return False, "Not found end-of-unpacking"
    return preceding_oep[0], "success"


def get_matched_signature(file_path):
    file = os.path.join(file_path)
    if not os.path.exists(file):
        return None
    with open(file, "r") as f:
        last_line = f.readlines()[-1]
        if "Packer Identified" in last_line:
            words = last_line.split("\t")
            for word in words:
                if word.startswith("0x"):
                    matched_signature = word
                    return matched_signature
    return None


def get_obfuscation_technique_sequence(packer_name, filename):
    def get_sequence(source_file, filename):
        # print("file_name = {}".format(file_name))
        with open(source_file, "r") as f:
            for line in f.readlines()[::-1]:
                if (packer_name in line) and (filename in line):  # and ("Packer Detected" in line) :
                    sequence = line.split("\t")[2]
                    return sequence
        return None

    # print("sequence")
    obfuscation_technique_sequence = get_sequence(packedSignature_path, filename)
    # print("address")
    obfuscation_technique_address = get_sequence(positionDetail_path, filename)
    # print("seq: {}".format(obfuscation_technique_sequence))
    # print("add: {}".format(obfuscation_technique_address))
    # print("Diff length: {} {} {}".format(
    #     len(obfuscation_technique_sequence.split('_')) == len(obfuscation_technique_address.split('_')),
    #     len(obfuscation_technique_sequence.split('_')), len(obfuscation_technique_address.split('_'))))
    # assert len(obfuscation_technique_sequence.split('_')) == len(obfuscation_technique_address.split('_'))
    return obfuscation_technique_sequence, obfuscation_technique_address


def get_sequence_by_address(address, obfuscation_technique_sequence, obfuscation_address_sequence):
    tech_seq = obfuscation_technique_sequence.split("_")
    add_seq = obfuscation_address_sequence.split("_")

    idx = add_seq.index(address[0:2] + address[4:])
    return "_".join(tech_seq[:idx + 1]), "_".join(add_seq[:idx + 1])


def get_end_of_unpacking_in_original_graph(G, node):
    for original_node in G.nodes:
        if node in original_node:
            return original_node
    return None


def get_OEP(packer_name, file_name, end_of_unpacking_address):
    def get_address_format(s):
        return s[1:11]

    packed_program_dot_file = os.path.join("data", "asm_cfg", packer_name,
                                           "{}_{}_model.dot".format(packer_name, file_name))
    original_graph = nx.DiGraph(read_dot(path=packed_program_dot_file))
    # G = get_removed_backed_graph(packer_name, file_name)
    # packed_program_graph = create_subgraph(G,
    #                                        address="-1", from_specific_node=False)

    # end_unpacking_node_name = "a{}{}".format(end_of_unpacking_address,
    #                                                    packed_program_graph.nodes[end_of_unpacking_address]["label"])

    end_unpacking_node_name = end_of_unpacking_address  # if node identity is pair <add, instruction>
    original_end_of_unpacking_node = get_end_of_unpacking_in_original_graph(original_graph,
                                                                            end_unpacking_node_name)

    n_child = 0
    child_nodes = []
    # print("original")
    # print(original_end_of_unpacking_node)
    for child_node in original_graph.successors(original_end_of_unpacking_node):
        n_child += 1
        child_nodes.append(child_node)

    if n_child == 0:
        return None, "not found OEP"
    if n_child == 1:
        return get_address_format(child_nodes[0]), "success"

    try:
        if n_child == 2:
            for child_node in child_nodes:
                if original_graph[original_end_of_unpacking_node][child_node]["label"] == "T":
                    return get_address_format(child_node), "success"
    except Exception as e:
        return None, str(e)

    return None, "too many candidates"


def get_entry_point_from_pefile(file):
    pe = pefile.PE(file)
    entry_point_address = "0x{:X}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    return entry_point_address


def verify_offset(entry_point, address):
    entry_point_10 = int(entry_point, 16)
    address_10 = int(address, 16)
    offset = str(hex(abs(entry_point_10 - address_10)))
    # print("offset = {}, offsets = {}".format(offset, offsets))
    return offset in offsets


def verify_asm(entry_point, address):
    pass


def search_entry_point_in_asm(entry_point, asm_file, packed_dot_file, original_dot_file):
    original_cfg = remove_back_edge(relabel_graph(nx.DiGraph(read_dot(path=original_dot_file))))
    packed_cfg = remove_back_edge(relabel_graph(nx.DiGraph(read_dot(path=packed_dot_file))))

    entry_point_of_original = list(original_cfg.nodes)[0]
    node_list_of_original, node_labels_of_original, original_labels_of_original, _ = convert_graph_to_vector(
        original_cfg, entry_point_of_original, from_specific_node=True, from_bottom=False, depth=5)

    data_original = Counter(list(node_labels_of_original.values()) + original_labels_of_original)
    unique_labels = sorted(list(set(list(node_labels_of_original.values()) + original_labels_of_original)))
    for node in packed_cfg.nodes:
        if not node.startswith("a"):
            continue
        address = node[1:11]
        # print("address = {}, verify: {}".format(address, verify_offset(entry_point, address)))
        if verify_offset(entry_point, address):
            node_list_of_packed, node_labels_of_packed, original_labels_of_packed, _ = convert_graph_to_vector(
                packed_cfg, address=node, from_specific_node=True, from_bottom=False, depth=5)
            data_packed_code = Counter(list(node_labels_of_packed.values()) + original_labels_of_packed)

            merged_unique_labels = sorted(
                list(set(unique_labels + list(node_labels_of_packed.values()) + original_labels_of_packed)))

            original_feature_vector = get_feature_vector(data_original, merged_unique_labels)
            packed_feature_vector = get_feature_vector(data_packed_code, merged_unique_labels)
            sim = cosine_similarity(original_feature_vector, packed_feature_vector)
            print("node: {}, sim = {}".format(node, sim))
    # save_address, save_instruction = None, None
    # with open(asm_file, "r") as f:
    #     for line in f:
    #         if ":" in line:
    #             address, instruction = line.split(":")
    #             if not verify_offset(entry_point, address):
    #                 continue
    #
    #             save_address, save_instruction = address, instruction
    # return save_address, save_instruction


# print(verify_offset("0x0001dffa", "0x0041dffa"))
# print(verify_offset("0x00012d6c", "0x01012d6c"))
asm_file = "data/asm_cfg/upx/upx_AccessEnum.exe_code.asm"
packed_dot_file = "data/asm_cfg/upx/upx_AccessEnum.exe_model.dot"
original_dot_file = "data/log_bepum_malware/AccessEnum.exe_model.dot"
entry_point = "0x00007a98"

search_entry_point_in_asm(entry_point, asm_file, packed_dot_file, original_dot_file)
