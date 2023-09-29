import glob
import os

path = "/media/hungpt/SSD-HUNG/OEP_detection/log_be_pum_malware_all/"

folders = ["first", "20230701", "20230711", "20230714", "20230722", "20230731"]

L = set()
for folder in folders:
    files = glob.glob(path + folder + "/*.log")
    for file in files:
        file_name = os.path.basename(file)
        if ("Backdoor" in file_name) or ("Trojan" in file_name):
            L.add(file_name)
print("len = {}".format(len(L)))


