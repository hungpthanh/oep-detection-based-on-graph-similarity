# from utils.preprocess_be_pum import get_OEP_of_UPX
import os

from common.models import BPCFG

packed_file_path = "data/packed_files.txt"
packedSignature_path = "data/packerSignature.txt"
positionDetail_path = "data/positionDetail.txt"


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
    if len(preceding_oep) == 0:
        return False
    return preceding_oep[0]


def get_matched_signature(file_path):
    file = os.path.join(file_path)
    if not os.path.exists(file):
        return None
    with open(file, "r") as f:
        last_line = f.readlines()[-1]
        if "Packer Identified" in last_line:
            words = last_line.split("\t")
            for word in words:
                if word.startswith("0x"):
                    matched_signature = word
                    return matched_signature
    return None


def get_obfuscation_technique_sequence(packer_name, filename):
    def get_sequence(file_name):
        # print("file_name = {}".format(file_name))
        with open(file_name, "r") as f:
            for line in f.readlines()[::-1]:
                if (packer_name in line) and (filename in line):  # and ("Packer Detected" in line) :
                    sequence = line.split("\t")[2]
                    return sequence
        return None

    # print("sequence")
    obfuscation_technique_sequence = get_sequence(packedSignature_path)
    # print("address")
    obfuscation_technique_address = get_sequence(positionDetail_path)
    # print("seq: {}".format(obfuscation_technique_sequence))
    # print("add: {}".format(obfuscation_technique_address))
    # print("Diff length: {} {} {}".format(
    #     len(obfuscation_technique_sequence.split('_')) == len(obfuscation_technique_address.split('_')),
    #     len(obfuscation_technique_sequence.split('_')), len(obfuscation_technique_address.split('_'))))
    # assert len(obfuscation_technique_sequence.split('_')) == len(obfuscation_technique_address.split('_'))
    return obfuscation_technique_sequence, obfuscation_technique_address


def get_sequence_by_address(address, obfuscation_technique_sequence, obfuscation_address_sequence):
    tech_seq = obfuscation_technique_sequence.split("_")
    add_seq = obfuscation_address_sequence.split("_")

    idx = add_seq.index(address[0:2] + address[4:])
    return "_".join(tech_seq[:idx + 1]), "_".join(add_seq[:idx + 1])