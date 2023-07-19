import argparse
import glob
import os
import random
random.seed(10)
import networkx as nx
from networkx.drawing.nx_agraph import read_dot

from utils.graph_utils import verify_cfg, relabel_graph, remove_back_edge
from utils.oep_utils import get_entry_point_from_pefile, get_oep_dataset, get_preceding_oep, \
    search_entry_point_in_cfg, get_oep_dataset_2
from utils.string_utils import get_file_name_from_log

parser = argparse.ArgumentParser()
parser.add_argument('--packer_names', nargs="+",
                    default=["upx", "aspack", "yodaC", "mew", "fsg", "pecompact", "petitepacked", "winupack", "MPRESS"])
parser.add_argument('--data_path', default="data", type=str)
parser.add_argument('--original_folder', default="/home/hungpt/Downloads/PackingData-master/Notpacked", type=str)

# Get the arguments
args = parser.parse_args()
oep_dictionary = get_oep_dataset()
#log_oep = open("new_oep_dataset_3.txt", "w")

oep_dictionary_2 = get_oep_dataset_2()


# def get
# def main():
#     for packer_name in args.packer_names:
#         # if packer_name != "upx":
#         #     continue
#         print("packer name: {}".format(packer_name))
#         log_files = glob.glob(os.path.join(args.data_path, "logs", "{}/*.log".format(packer_name)))
#
#         for log_file in log_files:
#
#             file_name = get_file_name_from_log(log_file)
#             # print(file_name)
#             # if file_name != "Hasher.exe":
#             #     continue
#
#             # print("File name = {}".format(file_name))
#             # print("File name: {}".format(file_name))
#             dot_file = os.path.join(args.data_path, "asm_cfg",
#                                     "{}/{}_{}_model.dot".format(packer_name, packer_name, file_name))
#             asm_file = os.path.join(args.data_path, "asm_cfg",
#                                     "{}/{}_{}_code.asm".format(packer_name, packer_name, file_name))
#             # if dot file or asm file donot exist => Cancel
#             if (not os.path.exists(dot_file)) or (not os.path.exists(asm_file)):
#                 continue
#
#             packed_dot_file_is_ok, msg = verify_cfg(dot_file)
#             if not packed_dot_file_is_ok:
#                 continue
#
#             # get OEP of the packed code
#             original_file = os.path.join(args.original_folder, file_name)
#             original_dot_file = os.path.join(args.data_path, "log_bepum_malware", "{}_model.dot".format(file_name))
#
#             original_file_is_ok, msg = verify_cfg(original_dot_file)
#             print("original_file_is_ok: {}".format(original_file_is_ok))
#             print("pass 1")
#             OEP = None
#             if original_file_is_ok:
#                 print("pass 2")
#                 entry_point = get_entry_point_from_pefile(original_file)
#                 print("ebtry_point = {}".format(entry_point))
#                 OEP = search_entry_point_in_cfg(entry_point, dot_file, original_dot_file)
#             else:
#                 print("pass 3")
#                 upx_dot_file = os.path.join(args.data_path, "asm_cfg", "upx", "upx_{}_model.dot".format(file_name))
#                 upx_asm_file = os.path.join(args.data_path, "asm_cfg", "upx", "upx_{}_code.asm".format(file_name))
#                 upx_is_ok, msg_upx = verify_cfg(upx_dot_file)
#                 if upx_is_ok:
#                     print("pass 4")
#                     oep_address = None
#                     with open(upx_asm_file, "r") as f:
#                         lines = [line for line in f]
#                         for idx, line in enumerate(lines):
#                             if "popa" in line:
#                                 oep_address = lines[idx + 7].strip().split(":")[0]
#                                 break
#                     # print("oep address upx = {}".format(oep_address))
#                     if oep_address is not None:
#                         # we can get the original CFG when it is packed by upx
#                         # Now, it equivalent when we have original file but sometime BE-PUM finish soon and
#                         # we can get original CFG
#                         cfg = nx.DiGraph(read_dot(path=upx_dot_file))
#                         for node in cfg.nodes:
#                             if node.startswith("a"):
#                                 address = node[1:11]
#                                 if address == oep_address:
#                                     OEP = node
#                                     break
#                         print("OEP for search = {}".format(OEP))
#                         OEP = search_entry_point_in_cfg("-1", dot_file, upx_dot_file, using_upx=True,
#                                                         oep_upx=OEP)
#
#             # Check whether a file is packed or not
#             packed_cfg = remove_back_edge(relabel_graph(nx.DiGraph(read_dot(path=dot_file))))
#
#             if OEP is not None:
#                 parent_of_OEP = [v for v in packed_cfg.predecessors(OEP)]
#                 if len(parent_of_OEP) == 0:
#                     print("File name: {}, This file is not packed".format(file_name))
#                     log_oep.writelines("{}_{},This file is not packed\n".format(packer_name, file_name))
#             print("File name: {}, OEP: {}".format(file_name, OEP))
#             log_oep.writelines("{}_{},{}\n".format(packer_name, file_name, OEP))
#     log_oep.close()


def split_train_test():
    data_of = {}
    for packer_name_file_name, oep_address in oep_dictionary_2.items():
        print(packer_name_file_name)
        packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
            packer_name_file_name.strip().split("_")[1:])
        if oep_address != "None":
            if not (packer_name_of_file in data_of):
                data_of[packer_name_of_file] = []
            data_of[packer_name_of_file].append(file_name)

    f_train = open("data/train.txt", "w")
    f_test = open("data/test.txt", "w")
    for packer_name, files in data_of.items():
        n_of_files = len(files)
        n_of_train = n_of_files // 10
        train_set = random.sample(files, n_of_train)
        test_set = [e for e in files if not (e in train_set)]
        print(packer_name)
        print(train_set)
        print(test_set)
        for train_file in train_set:
            f_train.writelines("{}_{}\n".format(packer_name, train_file))
        for test_file in test_set:
            f_test.writelines("{}_{}\n".format(packer_name, test_file))
    f_train.close()
    f_test.close()


if __name__ == '__main__':
    split_train_test()
    # main()