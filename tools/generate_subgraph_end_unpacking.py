import argparse
import os
import sys

sys.path.append('.')

import networkx as nx
from networkx.drawing.nx_agraph import read_dot
from tqdm import tqdm

from utils.graph_utils import create_subgraph
from utils.oep_utils import get_oep_dataset, get_preceding_oep

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="evaluation", type=str)
parser.add_argument('--packer_names', nargs="+",
                    default=["upx", "aspack", "MPRESS", "pecompact", "petitepacked", "mew", "fsg", "yodaC", "winupack"])

args = parser.parse_args()
oep_dictionary = get_oep_dataset()

data_folder_path = "data"


def main():
    packer_names = args.packer_names
    for file_name, oep_address in oep_dictionary.items():
        print("File name: {}".format(file_name))
        for packer_name in tqdm(packer_names):
            file_path = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                     "{}_{}_model.dot".format(packer_name, file_name))

            preceding_of_file, msg = get_preceding_oep(file_path, oep_dictionary[file_name])
            # print("packer name: {}, {}".format(packer_name, msg))
            if msg == "success":
                G1 = create_subgraph(dot_file=os.path.join(file_path),
                                     address=preceding_of_file, from_specific_node=True, label_with_address=True)
                nx.nx_agraph.write_dot(G1, "logs/log_subgraph/{}_{}.dot".format(packer_name, file_name))


if __name__ == '__main__':
    main()
