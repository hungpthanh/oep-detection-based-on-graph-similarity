import argparse
import json
import os
from collections import Counter

import numpy as np
from pandas.io.json import to_json
from sklearn.cluster import DBSCAN

from utils.graph_similarity_utils import convert_graph_to_vector, get_feature_vector
from utils.graph_utils import get_removed_backed_graph
from utils.oep_utils import get_oep_dataset_2, get_preceding_oep

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+", default=["upx"])
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--sample_files', nargs="+",
                    default=["AccessEnum.exe", "Cacheset.exe", "ADInsight.exe", "ADExplorer.exe"])
parser.add_argument('--train_path', default="data/train.txt", type=str)
parser.add_argument('--first_k', default=3, type=int)
# Get the arguments
args = parser.parse_args()
data_folder_path = "data"

oep_dictionary_2 = get_oep_dataset_2()


def get_packer_name_and_filename(packer_name_file_name):
    packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
        packer_name_file_name.strip().split("_")[1:])
    return packer_name_of_file, file_name


def construct_standard_vector(packer_name, packed_files):
    print("Process packer: {}".format(packer_name))
    data = {}
    merged_unique_labels = []
    for packed_file in packed_files:
        _, file_name = get_packer_name_and_filename(packed_file)
        packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                       "{}_model.dot".format(packed_file))
        oep_address = oep_dictionary_2[packed_file]
        preceding_oep, msg = get_preceding_oep(packed_dot_file, oep_address)
        if not preceding_oep:
            print("Packer: {}, file_name: {}, error: {}".format(packer_name, packed_file, msg))
            continue
        packed_graph = get_removed_backed_graph(packer_name, file_name)
        node_list_packed_file, node_labels_packed_file, original_labels_packed_file, _ = convert_graph_to_vector(
            packed_graph,
            address=preceding_oep)

        data[file_name] = Counter(list(node_labels_packed_file.values()) + original_labels_packed_file)
        merged_unique_labels = sorted(
            list(set(merged_unique_labels + list(node_labels_packed_file.values()) + original_labels_packed_file)))
    X = []
    idx = 0
    for packed_file in packed_files:
        _, file_name = get_packer_name_and_filename(packed_file)
        try:
            feature_vector = get_feature_vector(data[file_name], merged_unique_labels)
            print(feature_vector)
            X.append(feature_vector)
            idx += 1
        except Exception as e:
            pass
    X = np.asarray(X)
    clustering = DBSCAN(eps=0.05, min_samples=2, metric="cosine").fit(X)
    labels = clustering.labels_
    print(labels)
    standard_feature_vectors = {}
    n_sample_of = {}
    for idx in range(X.shape[0]):
        label = str(labels[idx])
        if label == -1:
            continue

        if label in n_sample_of:
            n_sample_of[label] += 1
        else:
            n_sample_of[label] = 1

        if not (label in standard_feature_vectors):
            standard_feature_vectors[label] = {}

        for idy, label_of_node in enumerate(merged_unique_labels):
            if not (label_of_node in standard_feature_vectors[label]):
                standard_feature_vectors[label][label_of_node] = 0.0
            standard_feature_vectors[label][label_of_node] += X[idx][idy]
    print(n_sample_of)
    for label in standard_feature_vectors.keys():
        for idx, label_of_node in enumerate(merged_unique_labels):
            standard_feature_vectors[label][label_of_node] /= n_sample_of[label]

    return standard_feature_vectors


def main():
    train_of = {}
    with open(args.train_path, "r") as f:
        for line in f:
            packer_name_of_file, file_name = get_packer_name_and_filename(line.strip())
            # if packer_name_of_file != "upx":
            #     continue
            if not (packer_name_of_file in train_of):
                train_of[packer_name_of_file] = []
            train_of[packer_name_of_file].append(line.strip())

        for packer_name, packed_files in train_of.items():
            standard_feature_vectors = construct_standard_vector(packer_name, packed_files)
            print(standard_feature_vectors)
            with open("configs/standard_feature_vectors/{}.json".format(packer_name), "w") as outfile:
                json.dump(standard_feature_vectors, outfile, indent=4)


if __name__ == '__main__':
    main()
