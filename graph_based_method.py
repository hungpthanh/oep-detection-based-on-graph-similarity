import argparse
import glob
import json
import os
import re
import time
from collections import Counter
import gc
import sys

from utils.graph_utils import create_subgraph, end_unpacking_sequence_samples, get_removed_backed_graph

sys.path.append('.')
import networkx as nx
import numpy as np
from tqdm import tqdm

from utils.graph_similarity_utils import cosine_similarity, build_subgraph_vector, convert_graph_to_vector
from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_OEP

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+", default=["upx"])
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--sample_files', nargs="+",
                    default=["AccessEnum.exe", "Cacheset.exe", "ADInsight.exe", "ADExplorer.exe"])
parser.add_argument('--log_path', default="logs/graph_based_method", type=str)
parser.add_argument('--first_k', default=3, type=int)
# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
data_folder_path = "data"

if not os.path.exists(args.log_path):
    os.mkdir(args.log_path)
log_file = open(args.log_path + "/{}.txt".format(args.packer_names), "w")
log_file.writelines("This experiments try to find packer name")
log_file.writelines("Packer names: {}\n".format(args.packer_names))
log_file.writelines("File name: {}\n".format(args.file_name))

with open('configs/standard_file.json') as stardard_file_json:
    standard_file = json.loads(stardard_file_json.read())


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
            sim = cosine_similarity(histograms['G1'], histograms[name])
            if sim > best_similarity:
                best_similarity = sim
                save_address = name

    except Exception as e:
        return None, None, str(e)

    return save_address, best_similarity, "Success"


def main():
    packer_names = args.packer_names
    print(packer_names)
    for packer_name in packer_names:
        total_sample = 0
        correct_sample = 0
        for file_name, oep_address in oep_dictionary.items():
            if file_name in args.sample_files:
                print("Packer: {}, file_name: {}, msg: This file is sample file".format(packer_name, file_name))
                log_file.writelines(
                    "Packer: {}, file_name: {}, msg: This file is sample file.\n".format(packer_name, file_name))
                continue
            packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                           "{}_{}_model.dot".format(packer_name, file_name))
            preceding_oep, msg = get_preceding_oep(packed_dot_file, oep_address)
            if not preceding_oep:
                print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                log_file.writelines("Packer: {}, file_name: {}, error: {}\n".format(packer_name, file_name, msg))
                continue

            total_sample += 1
            final_address = None
            final_score = 0
            predicted_packer = None
            # create information of packed file
            data, unique_labels, node_list, end_unpacking_sequences, msg = build_subgraph_vector(packer_name, file_name)

            if data is None:
                print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                log_file.writelines("Packer: {}, file_name: {}, error: {}\n".format(packer_name, file_name, msg))
                continue
            print("Search packer name and OEP:")
            for packer_name_candidate, sample_files in tqdm(standard_file.items()):
                for sample_file in sample_files:
                    # create graph for sample file
                    sample_file_path = os.path.join(data_folder_path, "asm_cfg", packer_name_candidate,
                                                    "{}_{}_model.dot".format(packer_name_candidate, sample_file))

                    sample_graph = get_removed_backed_graph(packer_name_candidate, sample_file)
                    preceding_sample_file, msg = get_preceding_oep(sample_file_path, oep_dictionary[sample_file])
                    node_list_sample_file, node_labels_sample_file, original_labels_sample_file, _ = convert_graph_to_vector(
                        sample_graph,
                        address=preceding_sample_file)

                    # update information of sample file
                    data['G1'] = Counter(list(node_labels_sample_file.values()) + original_labels_sample_file)

                    # create unique labels of G1 and sub graphs
                    merged_unique_labels = sorted(
                        list(set(unique_labels + list(node_labels_sample_file.values()) + original_labels_sample_file)))

                    # Finding end-of-unpacking
                    predicted_address, score, msg = end_of_unpacking_prediction(packer_name=packer_name_candidate,
                                                                                node_list=node_list,
                                                                                unique_labels=merged_unique_labels,
                                                                                data=data,
                                                                                end_unpacking_sequences=end_unpacking_sequences,
                                                                                first_k=args.first_k)

                    if score is None:
                        print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                        log_file.writelines(
                            "Packer: {}, file_name: {}, error: {}\n".format(packer_name, file_name, msg))
                        continue
                    if score > final_score:
                        final_score = score
                        final_address = predicted_address
                        predicted_packer = packer_name
                    # print(
                    #     "Packer: {}, file_name: {}, sample_file: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}".format(
                    #         packer_name, file_name, sample_file, preceding_oep, predicted_address, score))
                    # log_file.writelines(
                    #     "Packer: {}, file_name: {}, sample_file: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                    #         packer_name, file_name, sample_file, preceding_oep, predicted_address, score))
            print(
                "Final decision: {}, Packer: {}, packer_identification: {}, file_name: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                    bool(preceding_oep == final_address),
                    packer_name, predicted_packer, file_name, preceding_oep, final_address, final_score))
            log_file.writelines(
                "Final decision: {}, Packer: {}, packer_identification: {}, file_name: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                    bool(preceding_oep == final_address),
                    packer_name, predicted_packer, file_name, preceding_oep, final_address, final_score))
            if final_address == preceding_oep:
                correct_sample += 1
        print("The accuracy of packer: {} is {}".format(packer_name, 1.0 * correct_sample / total_sample))
        log_file.writelines(
            "The accuracy of packer: {} is {}\n".format(packer_name, 1.0 * correct_sample / total_sample))


def get_result(s):
    pattern_packer = r'The accuracy of packer: (.*?) is'
    pattern_accuracy = r'is\s+(.*)$'
    match_packer = re.search(pattern_packer, s)
    match_accuracy = re.search(pattern_accuracy, s)
    if match_packer:
        result_packer = match_packer.group(1)
        result_accuracy = match_accuracy.group(1)
        return result_packer, result_accuracy
    return None, None


def get_final_decision(text):
    import re
    end_of_unpacking_result = re.search(r'Final decision: ([^,]+)', text).group(1)
    packer = re.search(r'Packer: ([^,]+)', text).group(1)
    file_name = re.search(r'file_name: ([^,]+)', text).group(1)
    predicted_end_of_unpacking = re.search(r'predicted-end-of-unpacking: ([^,]+)', text).group(1)
    score = re.search(r'score: ([\d.]+)', text).group(1)
    return end_of_unpacking_result, packer, file_name, predicted_end_of_unpacking, score


def evaluate():
    log_files = glob.glob(args.log_path + '/*.*')
    results = {}
    count_sample = {}
    count_correctd_sample = {}

    prediction_data = {}
    for log_file in log_files:
        print("Processing on {}".format(log_file))
        with open(log_file, "r") as f:
            lines = [line for line in f]
            avg_score = []
            for line in tqdm(lines):
                if "The accuracy of packer" in line:
                    packer_name, accuracy = get_result(line)
                    results[packer_name] = accuracy
                if "Final decision" in line:
                    end_of_unpacking_result, packer_name, file_name, predicted_end_of_unpacking, score = get_final_decision(
                        line)
                    predicted_oep, msg = get_OEP(packer_name, file_name, predicted_end_of_unpacking)
                    if end_of_unpacking_result == "True":
                        avg_score.append(float(score))
                    if not packer_name in prediction_data:
                        prediction_data[packer_name] = {}
                    if end_of_unpacking_result == "True":
                        prediction_data[packer_name][file_name] = predicted_oep
                    else:
                        prediction_data[packer_name][file_name] = None
            print("avarage score is {}".format(np.mean(avg_score)))
    for packer_name, file_names in prediction_data.items():
        n_sample = len(prediction_data[packer_name])
        n_correct = 0
        for filename, predicted_oep in file_names.items():
            if (predicted_oep is not None) and (predicted_oep == oep_dictionary[filename]):
                n_correct += 1
        print("Packer: {}, end-of-unpacking accuracy: {:.3f}, OEP detection accuracy: {:.3f}, of sample: {}".format(
            packer_name,
            float(results[packer_name]),
            1.0 * n_correct / n_sample, n_sample))


if __name__ == '__main__':
    if args.mode == "detection":
        main()
    else:
        evaluate()
    log_file.close()
