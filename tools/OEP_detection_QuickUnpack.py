import glob

from utils.dataset_utils import get_test_list
import shutil
import os

from utils.oep_utils import get_entry_point_from_pefile, get_oep_dataset_2, verify_offset

oep_dictionary_2 = get_oep_dataset_2()
target_folder = "/media/hungpt/SSD-HUNG/test_Gunpacker"
source_folder = "/home/hungpt/Desktop/check_virustotal"

def get_packer_name_and_filename(packer_name_file_name):
    packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
        packer_name_file_name.strip().split("_")[1:])
    return packer_name_of_file, file_name

def get_OEP_of(filename, log):
    # print("log = {}".format(log))
    ok_name = False
    OEP = None
    with open(log, encoding = "ISO-8859-1") as f:
        for line in f:
            if filename in line:
                ok_name = True
            if "OEP..." in line:
                line = line.strip()
                OEP = line[-8:]
    if ok_name:
        return OEP
    return None

test_list = get_test_list()
print(len(test_list))
cnt = 0
number_of = {}
correct_of = {}
for file_name in test_list:
    # print(file_name)
    packer_name_of_file, original_file_name = get_packer_name_and_filename(file_name)

    if not (packer_name_of_file in number_of):
        number_of[packer_name_of_file] = 0
        correct_of[packer_name_of_file] = 0
    number_of[packer_name_of_file] += 1
    for index in range(1, 69):
        logs = glob.glob(os.path.join(target_folder, "batch{}".format(index) + "/*.txt"))
        for log in logs:

            oep = get_OEP_of(file_name, log)
            if oep is None:
                continue
            cnt += 1
            correct_oep = oep_dictionary_2[file_name][1:11]
            print("{},{},{},{},{}".format(cnt, file_name, oep, correct_oep, verify_offset(oep, correct_oep)))
            if ("0x"+oep).upper() == correct_oep.upper():
                correct_of[packer_name_of_file] += 1
            # if verify_offset("0x"+oep, correct_oep):



for key in number_of.keys():
    print("packer: {}, # of: {}, correct: {}".format(key, number_of[key], correct_of[key]))