import glob
import os.path
from shutil import copyfile

packer_folde = "/home/hungpt/Downloads/dataset-packed-pe-master/packed/TELock"
original_telock_folder = "/home/hungpt/Desktop/original_for_telock"
non_packed_folder = "/home/hungpt/Downloads/dataset-packed-pe-master/not-packed"

list_files = glob.glob(packer_folde + "/*.exe")

for file in list_files:
    # print(file)
    original_name_file = os.path.basename(file)[7:]
    # print(original_name_file)
    src = os.path.join(non_packed_folder, original_name_file)
    if not os.path.exists(src):
        continue
    path = "timeout 60m java -jar Main.jar asm/testcase/{}".format(original_name_file)
    print(path)
    # dst = os.path.join(original_telock_folder, original_name_file)
    # copyfile(src, dst)
