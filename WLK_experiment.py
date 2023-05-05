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
parser.add_argument('--packer_name', default="upx", type=str)
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--sample_file', default="AccessEnum.exe", type=str)
# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
data_folder_path = "data"


def main():
    log_file = open("logs/log2_{}_{}.txt".format(args.packer_name, args.file_name), "w")
    packer_names = ["aspack", "upx", "fsg", "MPRESS", "petitepacked", "yodaC", "pecompact", "winupack", "mew"]
    # packer_names = ["pecompact"]
    sample_file = args.sample_file
    # pecompact: AccessEnum
    G1, G2 = None, None
    for packer_name in packer_names:
        if packer_name != args.packer_name:
            continue
        print("packer name: {}".format(packer_name))
        log_file.writelines("packer name: {}\n".format(packer_name))
        sample_file_path = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                        "{}_{}_model.dot".format(packer_name, sample_file))
        preceding_sample_file = get_preceding_oep(sample_file_path, oep_dictionary[sample_file])

        G1 = create_subgraph(dot_file=os.path.join(sample_file_path),
                             address=preceding_sample_file)
        total_sample = 0
        correct_sample = 0
        for file_name, oep_address in oep_dictionary.items():
            if file_name == sample_file or file_name == "name" or file_name != args.file_name:
                continue
            # if file_name != "Cacheset.exe":
            #     continue
            try:
                print("File name: {}".format(file_name))
                # log_file.writelines("File name: {}".format(file_name))
                packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                               "{}_{}_model.dot".format(packer_name, file_name))
                if not os.path.exists(packed_dot_file):
                    log_file.writelines("{}: This file do not have dot file from BE-PUM\n".format(file_name))
                    continue

                # print("packed_dot_file: {}".format(packed_dot_file))
                preceding_oep = get_preceding_oep(packed_dot_file, oep_address)

                if not preceding_oep:
                    log_file.writelines("{}: Something wrong with preceding OEP\n".format(file_name))
                    continue
                node_list = list(create_subgraph(dot_file=packed_dot_file, address="-1",
                                                 from_specific_node=False).nodes)

                node_labels = get_WLK(G1, 2)
                unique_labels = list(node_labels.values())
                data = {'G1': Counter(list(node_labels.values()))}
                print("Generating subgraph of {} nodes:".format(len(node_list)))
                # log_file.writelines("Generating subgraph of {} nodes:".format(len(node_list)))
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
                best_similarity = 0
                save_address = "-1"
                for name in tqdm(node_list):
                    sim = cosine_similarity(histograms['G1'], histograms[name])
                    if sim > best_similarity:
                        best_similarity = sim
                        save_address = name
                total_sample += 1

                if save_address == preceding_oep:
                    correct_sample += 1
                print("packer: {}, file: {}, preceding_oep: {}, predicted_preceding_oep: {}".format(packer_name,
                                                                                                    file_name,
                                                                                                    preceding_oep,
                                                                                                    save_address))
                log_file.writelines(
                    "packer: {}, file: {}, preceding_oep: {}, predicted_preceding_oep: {}".format(packer_name,
                                                                                                  file_name,
                                                                                                  preceding_oep,
                                                                                                  save_address))
                # node_labels, data, unique_labels, G2 = None, None, None, None
                # del node_labels, data, unique_labels, G2
                # gc.collect()
            except Exception as e:
                print("Error in packer {} of {}: {}".format(packer_name, file_name, e))
                log_file.writelines("Error in packer {} of {}: {}".format(packer_name, file_name, e))
                pass
        if total_sample == 0:
            print("packer: {}, no samples valid or this file is sample file: {}".format(packer_name, args.sample_file))
            log_file.writelines(
                "packer: {}, no samples valid or this file is sample file: {}".format(packer_name, args.sample_file))
            continue
        print("The accuracy of packer: {} is {}".format(packer_name, 1.0 * correct_sample / total_sample))
        log_file.writelines("The accuracy of packer: {} is {}".format(packer_name, 1.0 * correct_sample / total_sample))
        # node_labels, data, unique_labels, G1, G2 = None, None, None, None
        # del node_labels, data, unique_labels, G1, G2
        # gc.collect()


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
