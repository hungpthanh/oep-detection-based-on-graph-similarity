import os.path

import networkx as nx
from networkx.drawing.nx_agraph import read_dot

from utils.dataset_utils import get_test_list, get_train_list
from utils.oep_utils import get_oep_dataset_2

oep_dictionary_2 = get_oep_dataset_2()
test_list = get_train_list() + get_test_list()
data_folder_path = "data"


def get_packer_name_and_filename(packer_name_file_name):
    packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
        packer_name_file_name.strip().split("_")[1:])
    return packer_name_of_file, file_name


def main():
    count_nodes = {}
    count_sample = {}
    for idx, item in enumerate(test_list):
        packer_name, file_name = get_packer_name_and_filename(item)
        if packer_name != "telock":
            continue
        print("packer name: {}, file_name: {}".format(packer_name, file_name))
        packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                       "{}_{}_model.dot".format(packer_name, file_name))
        original_dot_file = os.path.join(data_folder_path, "log_bepum_malware_winxp", "{}_model.dot".format(file_name))
        try:
            packed_code_cfg = nx.DiGraph(read_dot(path=packed_dot_file))
            original_code_cfg = nx.DiGraph(read_dot(path=original_dot_file))

            oep_address = oep_dictionary_2[item]

            node_in_packed = packed_code_cfg.nodes
            node_in_original = original_code_cfg.nodes

            # print("len packed = {}".format(len(node_in_packed)))
            # print("len original = {}".format(len(node_in_original)))
            # print("sub = {}".format(len(node_in_packed) - len(node_in_original)))
            if not (packer_name in count_nodes):
                count_nodes[packer_name] = 0
                count_sample[packer_name] = 0
            count_nodes[packer_name] += len(node_in_packed) - len(node_in_original)
            count_sample[packer_name] += 1
        except Exception as e:
            pass

    for key in count_nodes.keys():
        print("packer_name = {}, avg node = {:.2f}".format(key, 1.0 * count_nodes[key] / count_sample[key]))


if __name__ == '__main__':
    main()
