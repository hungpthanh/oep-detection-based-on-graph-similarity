import glob
import os

path = ""

folders = []

L = set()
for folder in folders:
    files = glob.glob(path + folder + "/*.log")
    for file in files:
        file_name = os.path.basename(file)
        if ("Backdoor" in file_name) or ("Trojan" in file_name):
            L.add(file_name)
print("len = {}".format(len(L)))


