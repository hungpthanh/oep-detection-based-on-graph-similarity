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

from utils.graph_similarity_utils import cosine_similarity, build_subgraph_vector, convert_graph_to_vector, \
    get_feature_vector
from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_OEP

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+",
                    default=["mew", "upx", "aspack", "fsg", "petitepacked", "pecompact", "MPRESS", "winupack", "yodaC"])

# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
data_folder_path = "data"
path_to_original_files = "/home/hungpt/Downloads/PackingData-master/Notpacked"
original_files = glob.glob(path_to_original_files + "/*.*")
original_file_names = [os.path.basename(original_file) for original_file in original_files]


def check_success_be_pum(log_file):
    try:
        with open(log_file, "r") as f:
            for line in f:
                if "Packer Identified" in line:
                    # pattern = r'Packer Identified:\s+([^\s]+)\s'
                    # match = re.search(pattern, line)
                    # # if match:
                    # #     result = match.group(1)
                    # #     print(result)  # Output: NONE
                    # # else:
                    # #     print("No match found.")
                    # if not match:
                        return True
    except Exception as e:
        return False
    return False


def main():
    packer_names = args.packer_names
    print(packer_names)
    for packer_name in packer_names:
        log_files = glob.glob(os.path.join(data_folder_path, "logs", packer_name) + "/*.*")
        for log_file in log_files:
            file_name = os.path.basename(log_file)[len("Log-{}".format(packer_name)) + 1:-4]
            if check_success_be_pum(log_file) and (not file_name in oep_dictionary):
                if file_name in original_file_names:
                    print("Packer: {}, File: {}, Exist original file: {}".format(packer_name, file_name, file_name in original_file_names))


if __name__ == '__main__':
    main()
