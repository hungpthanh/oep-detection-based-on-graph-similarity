import argparse
import glob
import json
import os
import re
import time
from collections import Counter
import gc
import sys

from utils.be_pum_utils import get_packer_name_BE_PUM
from utils.graph_utils import create_subgraph, get_removed_backed_graph, load_end_unpacking_sequence
from utils.dataset_utils import get_test_list
from utils.pack_identification_tool_utils import packer_identification_virus_total
from utils.pydetectpacker_utils import PyDetectPacker

end_unpacking_sequence_samples = load_end_unpacking_sequence()
sys.path.append('.')
import networkx as nx
import numpy as np
from tqdm import tqdm
from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_OEP, get_oep_dataset_2

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+", default=["upx"])
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--sample_files', nargs="+",
                    default=["AccessEnum.exe", "Cacheset.exe", "ADInsight.exe", "ADExplorer.exe"])
parser.add_argument('--log_path', default="logs/graph_based_method7", type=str)
parser.add_argument('--first_k', default=3, type=int)
# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
oep_dictionary_2 = get_oep_dataset_2()
data_folder_path = "data"

pypacker = PyDetectPacker()


def get_final_decision(text):
    import re
    end_of_unpacking_result = re.search(r'Final decision: ([^,]+)', text).group(1)
    packer = re.search(r'Packer: ([^,]+)', text).group(1)
    packer_identification = re.search(r'packer_identification: ([^,]+)', text).group(1)
    file_name = re.search(r'file_name: ([^,]+)', text).group(1)
    predicted_end_of_unpacking = re.search(r'predicted-end-of-unpacking: ([^,]+)', text).group(1)
    score = re.search(r'score: ([\d.]+)', text).group(1)
    return end_of_unpacking_result, packer, file_name, predicted_end_of_unpacking, score, packer_identification


def is_detect_correct(packer_name, answers):
    # print("packer name: {}".format(packer_name))
    if packer_name == "yodaC":
        packer_name = "yoda's Crypter"
    if packer_name == "petitepacked":
        packer_name = "Petite"
    # print("answer = {}".format(answers))
    for answer in answers:
        if packer_name.upper() in answer.upper():
            return True
    return False


def is_detect_correct_pydetectpacer(packer_name, answers):
    # print("packer name: {}".format(packer_name))
    if packer_name == "yodaC":
        packer_name = "yoda's Crypter"
    if packer_name == "petitepacked":
        packer_name = "Petite"

    for answer in answers:
        if ("Found PEID signature" in answer) and (packer_name.upper() in answer.upper()):
            return True
    return False


def main():
    log_files = glob.glob(args.log_path + '/*.*')
    results = {}
    prediction_data = {}
    packer_identification_data = {}

    acc_of = {}
    acc_pydetectpacker_of = {}
    number_of = {}
    for log_file in log_files:
        print("Processing on {}".format(log_file))
        with open(log_file, "r") as f:
            lines = [line for line in f]
            for line in tqdm(lines):
                if "Final decision" in line:
                    # if "upx" in line:
                    #     continue
                    end_of_unpacking_result, packer_name, file_name, predicted_end_of_unpacking, score, packer_identification = get_final_decision(
                        line)
                    print("packer name: {}, file name: {}".format(packer_name, file_name))
                    packed_file = "{}_{}".format(packer_name, file_name)
                    print("Path: {}".format(os.path.join("logs/virustotal", "{}.json".format(packed_file))))
                    if not os.path.exists(os.path.join("logs/virustotal", "{}.json".format(packed_file))):
                        print("miss: {}".format(packed_file))
                        continue
                    if not (packer_name in number_of):
                        number_of[packer_name] = 0
                        acc_of[packer_name] = 0
                        acc_pydetectpacker_of[packer_name] = 0

                    number_of[packer_name] += 1
                    print("hello")

                    predicted_packer = packer_identification_virus_total(packed_file)
                    packed_code_path = "/home/hungpt/Desktop/check_virustotal/{}".format(packed_file)

                    predicted_packer_pydetectpacker = pypacker.detect(packed_code_path)
                    print("pass get infor")
                    print(predicted_packer_pydetectpacker)
                    if is_detect_correct(packer_name, predicted_packer):
                        if not (packer_name in acc_of):
                            acc_of[packer_name] = 0
                        acc_of[packer_name] += 1
                    print("packer_name = {}".format(packer_name))
                    if predicted_packer_pydetectpacker is None:
                        continue
                    if is_detect_correct_pydetectpacer(packer_name, predicted_packer_pydetectpacker):
                        if not (packer_name in acc_pydetectpacker_of):
                            acc_pydetectpacker_of[packer_name] = 0
                        acc_pydetectpacker_of[packer_name] += 1
    print(acc_of)
    print(number_of)
    for packer, correct in acc_of.items():
        print("Packer: {}, correct: {} in total: {}".format(packer, correct, number_of[packer]))

    for packer, correct in acc_pydetectpacker_of.items():
        print("Packer: {}, correct: {} in total: {}".format(packer, correct, number_of[packer]))


if __name__ == '__main__':
    main()
