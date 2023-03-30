import os
import re

from utils.oep_utils import get_oep_dataset
from utils.pygraphviz_demmo import BPCFG

log_path = "data/logs"
asm_cfg_path = "data/asm_cfg"


def remove_unnecessary_char(s):
    return re.sub(r"[\n\t\s]*", "", s)

def get_end_of_unpacking(name):
    file = os.path.join(log_path, "Log-" + name + ".log")
    if not os.path.exists(file):
        return None
    with open(file, "r") as f:
        last_line = f.readlines()[-1]
        if "Packer Identified" in last_line:
            words = last_line.split("\t")
            for word in words:
                if word.startswith("0x"):
                    end_unpacking_address = word
                    return end_unpacking_address
    return None


def get_OEP_of_UPX(name):
    file = os.path.join(asm_cfg_path, name + "_code.asm")
    if not os.path.exists(file):
        return None, None
    with open(file, "r") as f:
        traces = []
        for line in f:
            # print(line)
            # print(line.split(":"))
            g = line.find(":")
            address = line[:g]
            instruction = remove_unnecessary_char(line[g + 1:])
            # address, instruction = line.split(":")
            traces.append((address, instruction))
        for idx, trace in enumerate(traces):
            # print(trace[1])
            if trace[1] == "popa":
                return traces[idx + 6][0], traces[idx + 7][0]
    return None, None


def update_information_UPX(packed_file_path):
    print("Go into update infro UPX")
    information = {}
    with open(packed_file_path, "r") as f:
        packed_file = [line.strip() for line in f]


    for name in packed_file:
        previous_OEP, OEP = get_OEP_of_UPX(name)
        if OEP is not None:
            if not (name in information):
                information[name] = {}
            information[name]["previous_OEP"] = previous_OEP
            information[name]["OEP"] = OEP

    for name in packed_file:
        end_unpacking_address = get_end_of_unpacking(name)
        if end_unpacking_address is not None:
            if not (name in information):
                information[name] = {}
            information[name]["end_unpacking"] = end_unpacking_address
    return information

def update_information_FSG(packed_file_path):
    information = {}
    with open(packed_file_path, "r") as f:
        packed_file = [line.strip() for line in f]
    oep_dictionary = get_oep_dataset()
    for idx, name in enumerate(packed_file):
        dot_file = os.path.join(asm_cfg_path, name + "_model.dot")
        if not os.path.exists(dot_file):
            continue
        print("name file: {}".format(name))
        try:
            cfg = BPCFG(dot_file)
        except Exception as e:
            print(e)
            continue
        # name = name[4:]

        if not name[4:] in oep_dictionary:
            print("Dont have the OEP of {}".format(name))
            continue
        OEP = oep_dictionary[name[4:]]
        previous_OEP = cfg.get_incoming_node(OEP)
        print("OEP = {}".format(OEP))
        print("previous OEP = {}".format(previous_OEP))
        if OEP is not None and len(previous_OEP) > 0:
            if not (name in information):
                information[name] = {}
            information[name]["previous_OEP"] = previous_OEP[0]
            information[name]["OEP"] = OEP
        #
        # break
    print(information)

    for name in packed_file:
        if not name in information:
            continue
        end_unpacking_address = get_end_of_unpacking(name)
        if end_unpacking_address is not None:
            if not (name in information):
                information[name] = {}
            information[name]["end_unpacking"] = end_unpacking_address
    print(len(information))
    return information