import argparse
import glob
import os
import time
from collections import Counter
import gc

from tqdm import tqdm

from common.models import create_subgraph
from utils.graph_similarity_utils import get_WLK, cosine_similarity
from utils.oep_utils import get_oep_dataset, get_preceding_oep

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+", default=["upx"])
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--sample_files', nargs="+", default=["AccessEnum.exe"])
# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
data_folder_path = "data"

log_file = open("logs/WLK_WINUPACK_2_sample_files/{}.txt".format(args.packer_names), "w")
log_file.writelines("Packer names: {}\n".format(args.packer_names))
log_file.writelines("Sample files: {}\n".format(args.sample_files))
log_file.writelines("File name: {}\n".format(args.file_name))


def get_histogram()
def end_of_unpacking_prediction(packer_name, sample_file, file_name):
    sample_file_path = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                    "{}_{}_model.dot".format(packer_name, sample_file))
    preceding_sample_file, msg = get_preceding_oep(sample_file_path, oep_dictionary[sample_file])

    G1 = create_subgraph(dot_file=os.path.join(sample_file_path),
                         address=preceding_sample_file)
    best_similarity = 0
    save_address = None
    try:
        packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                       "{}_{}_model.dot".format(packer_name, file_name))
        if not os.path.exists(packed_dot_file):
            return None, None, "This file do not have dot file from BE-PUM"

        node_list = list(create_subgraph(dot_file=packed_dot_file, address="-1",
                                         from_specific_node=False).nodes)

        node_labels = get_WLK(G1, 2)
        unique_labels = list(node_labels.values())
        data = {'G1': Counter(list(node_labels.values()))}
        print("Generating subgraph of {} nodes of {} packed by {}:".format(len(node_list), file_name, packer_name))
        for node in tqdm(node_list):
            G2 = create_subgraph(dot_file=packed_dot_file, address=node,
                                 from_specific_node=True)
            node_labels = get_WLK(G2, 2)
            unique_labels = unique_labels + list(node_labels.values())
            data[node] = Counter(list(node_labels.values()))
            # del G2
        unique_labels = sorted(list(set(unique_labels)))

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


            for sample_file in sample_files:
                predicted_address, score, msg = end_of_unpacking_prediction(packer_name, sample_file, file_name)
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
                "Final decision, Packer: {}, file_name: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}".format(
                    packer_name, file_name, preceding_oep, final_address, final_score))
            log_file.writelines(
                "Final decision, Packer: {}, file_name: {}, end-of-unpacking: {}, predicted-end-of-unpacking: {}, score: {}\n".format(
                    packer_name, file_name, preceding_oep, final_address, final_score))
            if final_address == preceding_oep:
                correct_sample += 1
        print("The accuracy of packer: {} is {}".format(packer_name, 1.0 * correct_sample / total_sample))
        log_file.writelines(
            "The accuracy of packer: {} is {}\n".format(packer_name, 1.0 * correct_sample / total_sample))


def evaluate():
    packer_names = ["aspack", "upx", "fsg", "MPRESS", "petitepacked", "yodaC", "pecompact", "winupack"]
    for packer_name in packer_names:
        total = 0
        corrected_sample = 0
        for file_name, oep_address in oep_dictionary.items():
            if file_name == "name":
                continue
            log_file = "logs/WLK_API_corrected/log2_{}_{}.txt".format(packer_name, file_name)
            with open(log_file, "r") as f:
                # line = f.readlines()[0]
                # print("packer_name: {}, file_name: {}, line: {}".format(packer_name, file_name, line))
                for line in f:
                    if "The accuracy of packer:" in line:
                        total += 1
                        if "1.0" in line:
                            corrected_sample += 1

        print("Accuracy of {}: {} on {} samples".format(packer_name, 1.0 * corrected_sample / total, total))


if __name__ == '__main__':
    if args.mode == "detection":
        main()
    else:
        evaluate()
