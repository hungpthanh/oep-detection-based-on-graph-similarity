import argparse
import glob
import os
import re
import time
from collections import Counter
import gc
import sys
import sys

from matplotlib import pyplot as plt
from sklearn.decomposition import PCA

sys.path.append('.')
from utils.graph_utils import create_subgraph, end_unpacking_sequence_samples, get_removed_backed_graph

sys.path.append('.')
from sklearn.cluster import DBSCAN
import networkx as nx
import numpy as np
from tqdm import tqdm

from utils.graph_similarity_utils import cosine_similarity_oep, build_subgraph_vector, convert_graph_to_vector, \
    get_feature_vector
from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_OEP, get_oep_dataset_2

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+",
                    default=["mew", "upx", "aspack", "fsg", "petitepacked", "pecompact", "MPRESS", "winupack", "yodaC"])

# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
data_folder_path = "data"


# if not os.path.exists(args.log_path):
#     os.mkdir(args.log_path)
# log_file = open(args.log_path + "/{}.txt".format(args.packer_names), "w")
# log_file.writelines("This experiments intergrate end-of-unpacking sequence to improve the accuracy")
# log_file.writelines("Packer names: {}\n".format(args.packer_names))
# log_file.writelines("Sample files: {}\n".format(args.sample_files))
# log_file.writelines("File name: {}\n".format(args.file_name))

oep_dictionary_2 = get_oep_dataset_2()
def main():
    packer_names = args.packer_names
    print(packer_names)
    for packer_name in packer_names:
        if packer_name != "winupack":
            continue
        data = {}
        merged_unique_labels = []
        for file_name, oep_address in oep_dictionary.items():
            packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                           "{}_{}_model.dot".format(packer_name, file_name))
            if not "{}_{}".format(packer_name, file_name) in oep_dictionary_2:
                continue


            oep_address = oep_dictionary_2["{}_{}".format(packer_name, file_name)]

            if oep_address == "None":
                continue
            preceding_oep, msg = get_preceding_oep(packed_dot_file, oep_address)
            if not preceding_oep:
                print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                # log_file.writelines("Packer: {}, file_name: {}, error: {}\n".format(packer_name, file_name, msg))
                continue

            packed_graph = get_removed_backed_graph(packer_name, file_name)
            preceding_packed_file, msg = get_preceding_oep(packed_dot_file, oep_address)
            if not preceding_packed_file:
                print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                continue
            node_list_packed_file, node_labels_packed_file, original_labels_packed_file, _ = convert_graph_to_vector(
                packed_graph,
                address=preceding_packed_file)

            data[file_name] = Counter(list(node_labels_packed_file.values()) + original_labels_packed_file)
            merged_unique_labels = sorted(
                list(set(merged_unique_labels + list(node_labels_packed_file.values()) + original_labels_packed_file)))
        X = []
        idx = 0
        for file_name, oep_address in oep_dictionary.items():
            try:
                feature_vector = get_feature_vector(data[file_name], merged_unique_labels)
                # print(file_name)
                # print(feature_vector)
                X.append(feature_vector)
                # if file_name == "whois.exe":
                #     idx_whois = idx
                # if file_name == "ADExplorer.exe":
                #     idx_ADExplorer = idx
                idx += 1
            except Exception as e:
                pass
        X = np.asarray(X)
        print(X.shape)
        # sim = cosine_similarity_oep(X[idx_whois], X[idx_ADExplorer])
        # print("sim = {}".format(sim))
        clustering = DBSCAN(eps=0.3, min_samples=2, metric="cosine").fit(X)
        labels = clustering.labels_
        print(labels)
        n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise_ = list(labels).count(-1)
        print("Estimated number of clusters: %d" % n_clusters_)
        print("Estimated number of noise points: %d" % n_noise_)

        # pca = PCA(n_components=2)
        # reduced = pca.fit_transform(X)
        # t = reduced.transpose()
        #
        # plt.scatter(t[0], t[1])
        # plt.savefig("logs/DBSCAN/{}.jpg".format(packer_name))
        # unique_labels = set(labels)
        # core_samples_mask = np.zeros_like(labels, dtype=bool)
        # core_samples_mask[clustering.core_sample_indices_] = True
        #
        # colors = [plt.cm.Spectral(each) for each in np.linspace(0, 1, len(unique_labels))]
        # for k, col in zip(unique_labels, colors):
        #     if k == -1:
        #         # Black used for noise.
        #         col = [0, 0, 0, 1]
        #
        #     class_member_mask = labels == k
        #
        #     xy = X[class_member_mask & core_samples_mask]
        #     plt.plot(
        #         xy[:, 0],
        #         xy[:, 1],
        #         "o",
        #         markerfacecolor=tuple(col),
        #         markeredgecolor="k",
        #         markersize=14,
        #     )
        #
        #     xy = X[class_member_mask & ~core_samples_mask]
        #     plt.plot(
        #         xy[:, 0],
        #         xy[:, 1],
        #         "o",
        #         markerfacecolor=tuple(col),
        #         markeredgecolor="k",
        #         markersize=6,
        #     )
        #
        # plt.title(f"Estimated number of clusters: {n_clusters_}")
        # # plt.show()
        # plt.savefig("logs/DBSCAN/{}.jpg".format(packer_name))


if __name__ == '__main__':
    main()
