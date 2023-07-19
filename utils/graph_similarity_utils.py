import glob
import json
import os
from collections import Counter

import networkx as nx
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from tqdm import tqdm

from utils.graph_utils import create_subgraph, get_opcode_sequence, get_removed_backed_graph
from sklearn.metrics.pairwise import cosine_similarity
data_folder_path = "data"


def get_WLK(G, h):
    node_labels = {n: G.nodes[n]["label"] for n in G.nodes}
    new_node_labels = {}
    for i in range(h):
        # Update node labels for each graph
        node_labels = update_node_labels(G, node_labels)
        for key, value in node_labels.items():
            new_key = "{}-{}".format(i + 1, key)
            new_value = "{}-{}".format(i + 1, value)
            new_node_labels[new_value] = new_value
    return new_node_labels


def weisfeiler_lehman_kernel(G1, G2, h):
    """
    Computes the Weisfeiler-Lehman kernel between two graphs.

    Args:
        G1: A NetworkX graph object representing the first graph.
        G2: A NetworkX graph object representing the second graph.
        h: The number of iterations to run the WL algorithm.

    Returns:
        The WL kernel value between the two graphs.
    """
    # Initialize node labels
    # Compute common node set
    # common_nodes = set(G1.nodes()) & set(G2.nodes())

    node_labels_1 = {n: G1.nodes[n]["label"] for n in G1.nodes}
    node_labels_2 = {n: G2.nodes[n]["label"] for n in G2.nodes}

    for i in range(h):
        # Update node labels for each graph
        node_labels_1 = update_node_labels(G1, node_labels_1)
        node_labels_2 = update_node_labels(G2, node_labels_2)

    # Compute histogram intersection kernel between label histograms
    G1_node_values = list(node_labels_1.values())
    G2_node_values = list(node_labels_2.values())
    unique_labels = sorted(list(set(G1_node_values + G2_node_values)))
    hist1 = []
    hist2 = []
    data1 = Counter(G1_node_values)
    data2 = Counter(G2_node_values)

    # print(data1)
    for idx, label in enumerate(unique_labels):
        if label in data1:
            hist1.append(data1[label])
        else:
            hist1.append(0)
        if label in data2:
            hist2.append(data2[label])
        else:
            hist2.append(0)

    # hist1 = compute_label_histogram(node_labels_1)
    # hist2 = compute_label_histogram(node_labels_2)

    # print(hist1)
    # print(hist2)
    # hist1_norm = hist1 / np.sum(hist1)
    # hist2_norm = hist2 / np.sum(hist2)
    # k = np.dot(hist1_norm, hist2_norm)

    # Truncate kernel value to 1 if it exceeds 1
    k = cosine_similarity_oep(hist1, hist2)
    # print(hist1.shape)
    # print(hist2.shape)
    # k = np.dot(hist1, hist2)

    return k, hist1, hist2


def update_node_labels(G, node_labels):
    """
    Updates node labels for a graph using the Weisfeiler-Lehman algorithm.

    Args:
        G: A NetworkX graph object.
        node_labels: A dictionary mapping node IDs to labels.

    Returns:
        A new dictionary mapping node IDs to updated labels.
    """
    new_labels = {}

    for n in G.nodes():
        # Get label for this node
        label = node_labels[n]

        # Get sorted list of neighbor labels
        neighbor_labels = sorted([node_labels[v] for v in G.predecessors(n)])

        # Concatenate label and neighbor labels
        new_label = label + ''.join(neighbor_labels)

        # Add new label to dictionary
        new_labels[n] = new_label

    return new_labels


def compute_label_histogram(node_labels):
    """
    Computes a histogram of the node labels for a graph.

    Args:
        node_labels: A dictionary mapping node IDs to labels.

    Returns:
        A 1D NumPy array representing the label histogram.
    """
    print(node_labels)
    labels = list(node_labels.values())
    print(labels)
    hist, _ = np.histogram(labels, bins=np.unique(labels))
    return hist


def cosine_similarity_oep(hist1, hist2):
    """
    Computes the cosine similarity between two histograms.

    Args:
        hist1: A 1D numpy array representing the first histogram.
        hist2: A 1D numpy array representing the second histogram.

    Returns:
        The cosine similarity between the two histograms.
    """
    # Compute dot product and magnitudes
    dot_product = np.dot(hist1, hist2)
    mag1 = np.sqrt(np.sum(np.square(hist1)))
    mag2 = np.sqrt(np.sum(np.square(hist2)))

    # Compute cosine similarity
    cosine = dot_product / (mag1 * mag2)
    # cosine = cosine_similarity(hist1.reshape(1, -1), hist2.reshape(1, -1))
    return cosine


def convert_graph_to_vector(removed_back_edge_G, address, from_specific_node=True, from_bottom=True, depth=-1):
    G1 = create_subgraph(removed_back_edge_G, address=address, from_specific_node=from_specific_node,
                         from_bottom=from_bottom, depth=depth)
    end_unpacking_seq = None
    if address != "-1" and from_bottom:
        end_unpacking_seq = get_opcode_sequence(G1, address)
    original_labels = [G1.nodes[node]["label"] for node in G1.nodes]
    node_list = G1.nodes
    node_labels = get_WLK(G1, 2)
    return node_list, node_labels, original_labels, end_unpacking_seq


def build_subgraph_vector(packer_name, file_name):
    packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                   "{}_{}_model.dot".format(packer_name, file_name))
    if not os.path.exists(packed_dot_file):
        return None, None, None, "This file do not have dot file from BE-PUM"
    removed_back_edge_G = get_removed_backed_graph(packer_name, file_name)
    nx.nx_agraph.write_dot(removed_back_edge_G,
                           "logs/keep_back_edges/removed_back_edge_{}_{}.dot".format(packer_name, file_name))
    node_list = list(create_subgraph(removed_back_edge_G, address="-1", from_specific_node=False).nodes)
    data = {}
    end_unpacking_sequences = {}
    unique_labels = []
    print("Generating subgraph of {} nodes of {} packed by {}:".format(len(node_list), file_name, packer_name))
    for node in tqdm(node_list):
        _, node_labels, original_labels, end_unpacking_seq = convert_graph_to_vector(removed_back_edge_G,
                                                                                     address=node,
                                                                                     from_specific_node=True)
        unique_labels = unique_labels + list(node_labels.values()) + original_labels
        data[node] = Counter(list(node_labels.values()) + original_labels)  # may add original nodes here
        end_unpacking_sequences[node] = end_unpacking_seq
    unique_labels = sorted(list(set(unique_labels)))
    return data, unique_labels, node_list, end_unpacking_sequences, "success"


def get_feature_vector(data, unique_labels):
    """
    :param data: The statistic counting label of a graph
    :param unique_labels: unique labels
    :return: feature vector of the graph
    """
    feature_vector = []
    for idx, label in enumerate(unique_labels):
        if label in data:
            feature_vector.append(data[label])
        else:
            feature_vector.append(0)
    return feature_vector


def load_standard_feature():
    standard_feature = {}
    packer_standard_files = glob.glob("configs/standard_feature_vectors/*.json")
    for packer_standard_file in packer_standard_files:
        packer_name = os.path.basename(packer_standard_file).split('.')[0]
        with open(packer_standard_file, "r") as f:
            standard_feature[packer_name] = json.loads(f.read())

    return standard_feature


