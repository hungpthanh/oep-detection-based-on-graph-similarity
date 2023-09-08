import glob
import os.path

import networkx as nx
import pefile
from networkx.drawing.nx_agraph import read_dot

from utils.oep_utils import verify_offset

data_folder = "/home/hungpt/workspace/research/oep-detection/data/asm_cfg/telock"
dot_files = glob.glob(data_folder + "/*.dot")
log_oep = open("oep_data/telock.txt", "w")

def find_address(address, file):
    with open(file, "r") as f:
        for line in f:
            if line.strip().startswith("0x"):
                if address.upper() in line[:10].upper():
                    # print(line)
                    return True
    return False


for dot_file in dot_files:
    if "test" in dot_file:
        continue
    # print(asm_file)
    # print("dot file: {}".format(dot_file))
    original_name = os.path.basename(dot_file)[7:-10]
    print(original_name)
    file = os.path.join("/media/hungpt/SSD-HUNG/original_telock", original_name)
    if not os.path.exists(file):
        continue
    pe = pefile.PE(file)
    entry_point = "{:X}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    try:
        cfg = nx.DiGraph(read_dot(path=dot_file))
        # cfg = BPCFG(dot_file)
        for node in cfg.nodes:
            # print(node)
            if not node.startswith("a"):
                continue
            address = node[1:11]
            if verify_offset(entry_point, address):
                print("OEP: {}".format(node))
                log_oep.writelines("{}_{},{}\n".format("telock", original_name, node))
    except Exception as e:
        print(e)
log_oep.close()
    # break
    # print(asm_file)
    # print(entry_point_address)
    # print("Found: {}".format(find_address(entry_point_address, asm_file)))

