import glob
import os.path

import pefile

data_folder = "/home/hungpt/workspace/research/oep-detection/data/asm_cfg/telock"
asm_files = glob.glob(data_folder + "/*.asm")


def find_address(address, file):
    with open(file, "r") as f:
        for line in f:
            if line.strip().startswith("0x"):
                if address.upper() in line[:10].upper():
                    # print(line)
                    return True
    return False


for asm_file in asm_files:
    if "test" in asm_file:
        continue
    # print(asm_file)
    original_name = os.path.basename(asm_file)[7:-9]
    file = os.path.join("/media/hungpt/SSD-HUNG/original_telock", original_name)
    if not os.path.exists(file):
        continue
    pe = pefile.PE(file)
    entry_point_address = "{:X}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    # print(asm_file)
    # print(entry_point_address)
    # print("Found: {}".format(find_address(entry_point_address, asm_file)))
    if find_address(entry_point_address, asm_file):
        print("timeout 60m java -jar Main.jar asm/testcase/{}".format(original_name))
