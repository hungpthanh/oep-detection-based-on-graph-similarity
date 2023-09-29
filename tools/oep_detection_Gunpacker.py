import glob

from utils.dataset_utils import get_test_list
import shutil
import os

from utils.oep_utils import get_entry_point_from_pefile, get_oep_dataset_2, verify_offset

oep_dictionary_2 = get_oep_dataset_2()
target_folder = "/media/hungpt/SSD-HUNG/OEP_detection/test_Gunpacker"
source_folder = "/home/hungpt/Desktop/check_virustotal"

def get_packer_name_and_filename(packer_name_file_name):
    packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
        packer_name_file_name.strip().split("_")[1:])
    return packer_name_of_file, file_name

test_list = get_test_list()
print(len(test_list))
cnt = 0
number_of = {}
correct_of = {}
for file_name in test_list:
    # print(file_name)
    packer_name_of_file, original_file_name = get_packer_name_and_filename(file_name)
    file_name_dump = "{}.GUnPacker.dump".format(file_name)
    if not (packer_name_of_file in number_of):
        number_of[packer_name_of_file] = 0
        correct_of[packer_name_of_file] = 0
    number_of[packer_name_of_file] += 1
    for index in range(1, 70):
        file_path = os.path.join(target_folder, "batch{}".format(index), file_name_dump)
        if os.path.exists(file_path):
            cnt += 1
            oep = get_entry_point_from_pefile(file_path)
            correct_oep = oep_dictionary_2[file_name][1:11]
            print("{},{},{},{},{}".format(cnt, file_name, oep, correct_oep, verify_offset(oep, correct_oep)))
            if verify_offset(oep, correct_oep):
                correct_of[packer_name_of_file] += 1


for key in number_of.keys():
    print("packer: {}, # of: {}, correct: {}".format(key, number_of[key], correct_of[key]))