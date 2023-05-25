import sys

from utils.graph_utils import get_opcode_sequence

sys.path.append('.')

import argparse
import os
import gc
from utils.graph_utils import create_subgraph
from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_OEP

parser = argparse.ArgumentParser()
parser.add_argument('--packer_names', nargs="+", default=["upx"])
parser.add_argument('--log_path', default="logs/opcode_sequence", type=str)

# Get the arguments
args = parser.parse_args()
gc.enable()
oep_dictionary = get_oep_dataset()
data_folder_path = "data"


def main():
    packer_names = args.packer_names
    print(packer_names)
    for packer_name in packer_names:
        with open(args.log_path + "/node_pair_{}.txt".format(packer_name), "w") as f:
            for file_name, oep_address in oep_dictionary.items():
                packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                               "{}_{}_model.dot".format(packer_name, file_name))
                preceding_oep, msg = get_preceding_oep(packed_dot_file, oep_address)

                if not preceding_oep:
                    print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                    # f.writelines("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                    continue

                G1 = create_subgraph(dot_file=os.path.join(packed_dot_file),
                                     address=preceding_oep, from_specific_node=True)
                seq = get_opcode_sequence(G1, preceding_oep)
                line = "_".join(seq)
                f.writelines(line + "\n")


if __name__ == '__main__':
    main()
