import argparse
import glob
import json
import os
import re
import time
from collections import Counter
import gc
import sys

from utils.be_pum_utils import get_packer_name_BE_PUM, check_finish_running, get_packer_name_in_BE_PUM
from utils.graph_utils import create_subgraph, get_removed_backed_graph, load_end_unpacking_sequence, verify_cfg
from utils.dataset_utils import get_test_list, get_inference_list

end_unpacking_sequence_samples = load_end_unpacking_sequence()
sys.path.append('.')
import networkx as nx
import numpy as np
from tqdm import tqdm

from utils.graph_similarity_utils import cosine_similarity_oep, build_subgraph_vector, convert_graph_to_vector, \
    load_standard_feature, build_subgraph_vector_inference
from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_OEP, get_oep_dataset_2

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+", default=["upx"])
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--inference_file', default="inference3.txt", type=str)
parser.add_argument('--sample_files', nargs="+",
                    default=["AccessEnum.exe", "Cacheset.exe", "ADInsight.exe", "ADExplorer.exe"])
parser.add_argument('--log_path', default="logs/graph_based_method6", type=str)
parser.add_argument('--first_k', default=5, type=int)
# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
oep_dictionary_2 = get_oep_dataset_2()
data_folder_path = "data"

if not os.path.exists(args.log_path):
    os.mkdir(args.log_path)
log_file = open(args.log_path + "/{}.txt".format(args.inference_file), "w")
log_file.writelines("Inference")
log_file.writelines("Packer names: {}\n".format(args.packer_names))
log_file.writelines("File name: {}\n".format(args.file_name))

with open('configs/standard_file.json') as stardard_file_json:
    standard_file = json.loads(stardard_file_json.read())

standard_feature = load_standard_feature()

inference_list = get_inference_list()

def end_of_unpacking_prediction(packer_name, node_list, unique_labels, data, end_unpacking_sequences, first_k=-1):
    best_similarity = 0
    save_address = None
    try:
        histograms = {}
        # print("Calculating histogram:")
        for idx, label in enumerate(unique_labels):
            for name in ['G1'] + node_list:
                if not (name in histograms):
                    histograms[name] = []
                if label in data[name]:
                    histograms[name].append(data[name][label])
                else:
                    histograms[name].append(0)

        # print("Searching for best matching graph:")
        for name in node_list:
            check_end_unpacking_sequence = True if first_k == -1 else False
            for end_unpacking_seq_sample in end_unpacking_sequence_samples[packer_name]:
                if end_unpacking_sequences[name][:first_k] == end_unpacking_seq_sample[:first_k]:
                    check_end_unpacking_sequence = True
            if not check_end_unpacking_sequence:
                continue
            sim = cosine_similarity_oep(histograms['G1'], histograms[name])
            if sim > best_similarity:
                best_similarity = sim
                save_address = name

    except Exception as e:
        return None, None, str(e)

    return save_address, best_similarity, "Success"


def main():
    packer_names = args.packer_names
    print(packer_names)
    total_sample = 0
    running_sample = 0
    for idx, file_name in enumerate(inference_list):

        # print("File name: {}".format(file_name))
        if file_name != "Trojan.Win32.DNSChanger.flc":
            continue
        packed_log_file = os.path.join(data_folder_path, "log_bepum_malware", "Log-" + file_name + ".log")
        running_sample += 1
        # if running_sample < 475:
        #     continue
        print("running sample = {}".format(running_sample))
        if not check_finish_running(packed_log_file):
            continue

        packer_name_be_pum = get_packer_name_in_BE_PUM(packed_log_file)
        total_sample += 1
        final_address = None
        final_score = 0
        predicted_packer = None
        # create information of packed file

        dot_file = os.path.join(data_folder_path, "log_bepum_malware", "{}_model.dot".format(file_name))
        # print("verify: {}".format(verify_cfg(dot_file)))
        if not verify_cfg(dot_file)[0]:
            continue

        # print("dot file: {}".format(dot_file))
        data, unique_labels, node_list, end_unpacking_sequences, msg = build_subgraph_vector_inference(file_name)

        if data is None:
            print("file_name: {}, error: {}".format(file_name, msg))
            log_file.writelines("file_name: {}, error: {}\n".format(file_name, msg))
            continue
        print("Search packer name and OEP:")
        for packer_name_candidate, sample_files in tqdm(standard_feature.items()):
            for _, feature in sample_files.items():
                # update information of sample file
                data['G1'] = feature
                # create unique labels of G1 and sub graphs
                merged_unique_labels = sorted(list(set(unique_labels + list(feature.keys()))))
                # Finding end-of-unpacking
                predicted_address, score, msg = end_of_unpacking_prediction(packer_name=packer_name_candidate,
                                                                            node_list=node_list,
                                                                            unique_labels=merged_unique_labels,
                                                                            data=data,
                                                                            end_unpacking_sequences=end_unpacking_sequences,
                                                                            first_k=args.first_k)

                if score is None:
                    print("file_name: {}, error: {}".format(file_name, msg))
                    log_file.writelines(
                        "file_name: {}, error: {}\n".format(file_name, msg))
                    continue
                if score > final_score:
                    final_score = score
                    final_address = predicted_address
                    predicted_packer = packer_name_candidate
        print(
            "Inference decision: packer_name_be_pum: {}, packer_identification: {}, file_name: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                packer_name_be_pum, predicted_packer, file_name, final_address, final_score))
        log_file.writelines(
            "Inference decision: packer_name_be_pum: {}, packer_identification: {}, file_name: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                packer_name_be_pum, predicted_packer, file_name, final_address, final_score))

def get_final_decision(text):
    import re
    end_of_unpacking_result = re.search(r'Final decision: ([^,]+)', text).group(1)
    packer = re.search(r'Packer: ([^,]+)', text).group(1)
    packer_identification = re.search(r'packer_identification: ([^,]+)', text).group(1)
    file_name = re.search(r'file_name: ([^,]+)', text).group(1)
    predicted_end_of_unpacking = re.search(r'predicted-end-of-unpacking: ([^,]+)', text).group(1)
    score = re.search(r'score: ([\d.]+)', text).group(1)
    return end_of_unpacking_result, packer, file_name, predicted_end_of_unpacking, score, packer_identification


if __name__ == '__main__':
    main()

