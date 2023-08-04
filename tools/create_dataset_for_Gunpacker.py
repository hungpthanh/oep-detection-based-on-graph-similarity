import glob

from utils.dataset_utils import get_test_list
import shutil
import os

target_folder = "/media/hungpt/SSD-HUNG/test_Gunpacker"
source_folder = "/home/hungpt/Desktop/check_virustotal"

# test_list = get_test_list()
# print(len(test_list))
# for file_name in test_list:
#     print(file_name)
#     if "packman" in file_name:
#         src = os.path.join(source_folder, file_name)
#
#         if not os.path.exists(src):
#             continue
#         dst = os.path.join(target_folder, file_name)
#         shutil.copyfile(src, dst)

files = glob.glob(target_folder + "/*.exe")
cnt = 0
cnt_batch = 6
for idx, file in enumerate(files):
    cnt += 1
    file_name = os.path.basename(file)
    print(file)
    if cnt % 10 == 1:
        cnt_batch += 1
        os.mkdir(os.path.join(target_folder, "batch{}".format(cnt_batch)))
    file_folder = os.path.join(target_folder, "batch{}".format(cnt_batch), file_name)
    shutil.copyfile(file, file_folder)
