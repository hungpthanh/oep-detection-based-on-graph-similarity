import argparse
import glob
import os
import re
import time
from collections import Counter
import gc

import numpy as np
from tqdm import tqdm

from utils.graph_similarity_utils import cosine_similarity, build_subgraph_vector, convert_graph_to_vector
from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_OEP

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+", default=["upx"])
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--sample_files', nargs="+", default=["AccessEnum.exe"])
parser.add_argument('--log_path', default="logs/WLK_original_identity_new_WLK", type=str)
# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
data_folder_path = "data"

log_file = open(args.log_path + "/{}.txt".format(args.packer_names), "w")
log_file.writelines("Packer names: {}\n".format(args.packer_names))
log_file.writelines("Sample files: {}\n".format(args.sample_files))
log_file.writelines("File name: {}\n".format(args.file_name))


def end_of_unpacking_prediction(node_list, unique_labels, data):
    best_similarity = 0
    save_address = None
    try:
        histograms = {}
        print("Calculating histogram:")
        for idx, label in enumerate(unique_labels):
            for name in ['G1'] + node_list:
                if not (name in histograms):
                    histograms[name] = []
                if label in data[name]:
                    histograms[name].append(data[name][label])
                else:
                    histograms[name].append(0)

        print("Searching for best matching graph:")
        for name in tqdm(node_list):
            sim = cosine_similarity(histograms['G1'], histograms[name])
            if sim > best_similarity:
                best_similarity = sim
                save_address = name

    except Exception as e:
        return None, None, str(e)

    return save_address, best_similarity, "Success"


def main():
    packer_names = args.packer_names
    sample_files = args.sample_files

    print(packer_names)
    for packer_name in packer_names:
        total_sample = 0
        correct_sample = 0
        for file_name, oep_address in oep_dictionary.items():
            if file_name != "md5summer.exe":
                continue
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

            # create information of packed file
            data, unique_labels, node_list, msg = build_subgraph_vector(packer_name, file_name)
            if data is None:
                print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                log_file.writelines("Packer: {}, file_name: {}, error: {}\n".format(packer_name, file_name, msg))
                continue

            for sample_file in sample_files:
                # create graph for sample file
                sample_file_path = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                                "{}_{}_model.dot".format(packer_name, sample_file))
                preceding_sample_file, msg = get_preceding_oep(sample_file_path, oep_dictionary[sample_file])
                print("preceding_sample_file: {}".format(preceding_sample_file))
                node_list_sample_file, node_labels_sample_file, original_labels_sample_file = convert_graph_to_vector(
                    packer_name, sample_file,
                    address=preceding_sample_file)

                # update information of sample file
                data['G1'] = Counter(list(node_labels_sample_file.values()) + original_labels_sample_file)

                # create unique labels of G1 and sub graphs
                merged_unique_labels = sorted(
                    list(set(unique_labels + list(node_labels_sample_file.values()) + original_labels_sample_file)))

                # Finding end-of-unpacking
                predicted_address, score, msg = end_of_unpacking_prediction(node_list=node_list,
                                                                            unique_labels=merged_unique_labels,
                                                                            data=data)

                if score is None:
                    print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                    log_file.writelines("Packer: {}, file_name: {}, error: {}\n".format(packer_name, file_name, msg))
                    continue
                if score > final_score:
                    final_score = score
                    final_address = predicted_address
                print(
                    "Packer: {}, file_name: {}, sample_file: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}".format(
                        packer_name, file_name, sample_file, preceding_oep, predicted_address, score))
                log_file.writelines(
                    "Packer: {}, file_name: {}, sample_file: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                        packer_name, file_name, sample_file, preceding_oep, predicted_address, score))
            print(
                "Final decision: {}, Packer: {}, file_name: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                    bool(preceding_oep == final_address),
                    packer_name, file_name, preceding_oep, final_address, final_score))
            log_file.writelines(
                "Final decision: {}, Packer: {}, file_name: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                    bool(preceding_oep == final_address),
                    packer_name, file_name, preceding_oep, final_address, final_score))
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
