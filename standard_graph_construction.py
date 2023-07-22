import argparse
import json
import os
from collections import Counter

import numpy as np
from pandas.io.json import to_json
from sklearn.cluster import DBSCAN

from utils.dataset_utils import get_train_list
from utils.graph_similarity_utils import convert_graph_to_vector, get_feature_vector
from utils.graph_utils import get_removed_backed_graph, get_opcode_sequence
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
train_list = get_train_list()
oep_dictionary_2 = get_oep_dataset_2()


def get_packer_name_and_filename(packer_name_file_name):
    packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
        packer_name_file_name.strip().split("_")[1:])
    return packer_name_of_file, file_name


def frequency_feature_vecter_computation(packer_name, packed_files):
    print("Process packer: {}".format(packer_name))
    data = {}
    merged_unique_labels = []
    opcode_sequence = {}
    for packed_file in packed_files:
        _, file_name = get_packer_name_and_filename(packed_file)
        packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                       "{}_model.dot".format(packed_file))
        oep_address = oep_dictionary_2[packed_file]
        print("oep_address = {}".format(oep_address))
        preceding_oep, msg = get_preceding_oep(packed_dot_file, oep_address)
        if not preceding_oep:
            print("Packer: {}, file_name: {}, error: {}".format(packer_name, packed_file, msg))
            continue
        packed_graph = get_removed_backed_graph(packer_name, file_name)
        node_list_packed_file, node_labels_packed_file, original_labels_packed_file, _ = convert_graph_to_vector(
            packed_graph,
            address=preceding_oep)

        data[file_name] = Counter(list(node_labels_packed_file.values()) + original_labels_packed_file)
        opcode_sequence[file_name] = get_opcode_sequence(packed_graph, preceding_oep)
        merged_unique_labels = sorted(
            list(set(merged_unique_labels + list(node_labels_packed_file.values()) + original_labels_packed_file)))

    return data, opcode_sequence, merged_unique_labels


def standard_generation(packed_files, opcode_sequence, labels, X, merged_unique_labels, first_k=5):
    standard_feature_vectors = {}
    n_sample_of = {}
    opcode_sequence_of_label = {}

    # for packed_file in packed_files:
    #     _, file_name = get_packer_name_and_filename(packed_file)

    for idx in range(len(packed_files)):
        label = str(labels[idx])
        if label == -1:
            continue
        if not label in opcode_sequence_of_label:
            opcode_sequence_of_label[label] = []

        _, file_name = get_packer_name_and_filename(packed_files[idx])
        opcode_sequence_of_label[label].append(opcode_sequence[file_name])

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
    # Check condition opcode sequence in group have to have the same sequence > 0
    for cluster_id, opcode_sequences in opcode_sequence_of_label.items():
        for idx in range(len(opcode_sequences)):
            if opcode_sequences[idx][:first_k] != opcode_sequences[0][:first_k]:
                return standard_feature_vectors, opcode_sequence_of_label, None

    # for cluster_id in opcode_sequence_of_label.keys():
    #     for cluster_other_id in opcode_sequence_of_label.keys():
    #         if cluster_other_id != cluster_id:
    #             if opcode_sequence_of_label[cluster_other_id][0][:first_k] == opcode_sequence_of_label[cluster_id][0][
    #                                                                           :first_k]:
    #                 return standard_feature_vectors, opcode_sequence_of_label, 1
    # only check other groups

    return standard_feature_vectors, opcode_sequence_of_label, n_sample_of


def construct_standard_vector(packer_name, packed_files):
    print("Process packer: {}".format(packer_name))
    data, opcode_sequence, merged_unique_labels = frequency_feature_vecter_computation(packer_name, packed_files)

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
    eps = 0.05
    l_eps, r_eps = 0, 1

    X = np.asarray(X)
    # for idx in range(X.shape[0] - 1):
    #     for idy in range(X.shape[0]):
    #         # print(cosine_similarity_oep(X[idx], X[idy]))
    #         print("{:.2f} ".format(cosine_similarity_oep(X[idx], X[idy])), end="")
    #     print()

    # optimal_standard_feature_vectors, optimal_opcode_sequence_of_label, optimal_n_sample_of = None, None, None
    eps_default = 0.3
    while True:
        # mid = (l_eps + r_eps) / 2
        # print("index: {} {} {}".format(l_eps, r_eps, mid))
        # if abs(r_eps - l_eps) < 0.001:
        #     break
        print("esp = {}".format(eps_default))
        if eps_default <= 0:
            break
        clustering = DBSCAN(eps=eps_default, min_samples=2, metric="cosine").fit(X)
        labels = clustering.labels_

        standard_feature_vectors, opcode_sequence_of_label, n_sample_of = standard_generation(packed_files,
                                                                                              opcode_sequence,
                                                                                              labels, X,
                                                                                              merged_unique_labels)
        # if standard_feature_vectors is not None:
        #     break
        # if n_sample_of is None:
        #     r_eps = mid
        # else:
        #     l_eps = mid
        if n_sample_of is None:
            eps_default -= 0.01
        else:
            optimal_standard_feature_vectors = standard_feature_vectors
            optimal_opcode_sequence_of_label = opcode_sequence_of_label
            optimal_n_sample_of = n_sample_of
            break

    assert X.shape[0] == len(packed_files)
    for label in optimal_standard_feature_vectors.keys():
        for idx, label_of_node in enumerate(merged_unique_labels):
            optimal_standard_feature_vectors[label][label_of_node] /= optimal_n_sample_of[label]

    # Save end-of-sequence
    with open("configs/end_of_unpacking_sequence.txt", "a") as f:
        for label, opcode_sequences in optimal_opcode_sequence_of_label.items():
            for opcode_sequence in opcode_sequences:
                print(opcode_sequence)
            max_length = min([len(seq) for seq in opcode_sequences])
            is_diff = False
            for idx in range(0, max_length):
                opcode = opcode_sequences[0][idx]
                for opcode_sequence in opcode_sequences:
                    if opcode_sequence[idx] != opcode:
                        is_diff = True
                        break
                if is_diff:
                    line = "_".join(opcode_sequences[0][:idx])
                    f.writelines("{},{}\n".format(packer_name, line))
                    break
            if not is_diff:
                line = "_".join(opcode_sequences[0][:max_length])
                f.writelines("{},{}\n".format(packer_name, line))
    return optimal_standard_feature_vectors


def main():
    train_of = {}
    for line in train_list:
        packer_name_of_file, file_name = get_packer_name_and_filename(line.strip())
        if packer_name_of_file != "packman" and packer_name_of_file != "jdpack":
            continue
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
