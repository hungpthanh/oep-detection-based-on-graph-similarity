# from utils.preprocess_be_pum import get_OEP_of_UPX
import os

from common.models import BPCFG

packed_file_path = "data/packed_files.txt"


# def build_OEP_dataset(packed_file_path):
#     information = {}
#     with open(packed_file_path, "r") as f:
#         packed_file = [line.strip() for line in f]
#
#     import csv
#
#     # open the file in the write mode
#     with open('OEP_dataset.csv', 'w') as f:
#         # create the csv writer
#         writer = csv.writer(f)
#
#         fieldnames = ['name', 'OEP']
#         # writer = csv.DictWriter(f, fieldnames=fieldnames)
#         # write a row to the csv file
#         names = []
#         oep_address = []
#         writer.writerow(fieldnames)
#         for name in packed_file:
#             previous_OEP, OEP = get_OEP_of_UPX(name)
#             if OEP is not None:
#                 if not (name in information):
#                     information[name] = {}
#                     names.append(name)
#                     oep_address.append(OEP)
#                     writer.writerow([name, OEP])
#                 information[name]["previous_OEP"] = previous_OEP
#
#                 information[name]["OEP"] = OEP
#
#         # writer.writerow([list_1[w], list_2[w]])


# build_OEP_dataset(packed_file_path)

def get_oep_dataset():
    results = {}
    with open("OEP_dataset.csv", "r") as f:
        for line in f:
            line = line.strip()
            name, oep = line.split(',')
            results[name] = oep
    return results


def get_preceding_oep(file_path, oep_address):
    dot_file = file_path
    if not os.path.exists(dot_file):
        return False
    try:
        cfg = BPCFG(dot_file)
    except Exception as e:
        print(e)
        return False
    preceding_oep = cfg.get_incoming_node(oep_address)
    return preceding_oep[0]
