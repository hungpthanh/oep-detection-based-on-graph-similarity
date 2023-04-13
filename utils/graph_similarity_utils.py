from collections import Counter

import networkx as nx
import numpy as np


def get_WLK(G, h):
    node_labels = {n: G.nodes[n]["label"] for n in G.nodes}
    for i in range(h):
        # Update node labels for each graph
        node_labels = update_node_labels(G, node_labels)
    return node_labels

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
    k = cosine_similarity(hist1, hist2)
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


def cosine_similarity(hist1, hist2):
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

    return cosine