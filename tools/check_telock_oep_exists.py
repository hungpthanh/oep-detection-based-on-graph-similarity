import glob
import os.path
import shutil

import pefile

data_folder = "/home/hungpt/workspace/research/oep-detection/data/asm_cfg/telock"
asm_files = glob.glob(data_folder + "/*.asm")

checked_sample_telocks = "/media/hungpt/SSD-HUNG/29_samples_telocks"
not_packed_folder = "/home/hungpt/Downloads/dataset-packed-pe-master/not-packed"
packed_telock_folder = "/home/hungpt/Downloads/dataset-packed-pe-master/packed/TELock"


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

    if find_address(entry_point_address, asm_file):
        print("timeout 60m java -jar Main.jar asm/testcase/{}".format(original_name))
        # copy original
        src = os.path.join(not_packed_folder, original_name)
        dst = os.path.join(checked_sample_telocks, "original", original_name)
        shutil.copyfile(src, dst)
        # copy packed codes telock
        src = os.path.join(packed_telock_folder, "{}_{}".format("telock", original_name))
        dst = os.path.join(checked_sample_telocks, "packed", "{}_{}".format("telock", original_name))
        shutil.copyfile(src, dst)
