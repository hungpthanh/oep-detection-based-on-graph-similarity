import json
import os


def get_packer_name_BE_PUM(packer_name, file_name):
    with open('configs/standard_file.json') as stardard_file_json:
        standard_file = json.loads(stardard_file_json.read())
        packer_name_lists = list(standard_file.keys())
        # print(packer_name_lists)
    with open("data/logs/{}/Log-{}_{}.log".format(packer_name, packer_name, file_name)) as f:
        last_line = f.readlines()[-1].strip()
        if "Packer Identified" in last_line:
            words = last_line.split("\t")
            predicted_packer_name = words[0].split(' ')[-1]
            for name in packer_name_lists:
                if name == "yodaC":
                    search_name = "Crypter"
                elif name == "winupack":
                    search_name = "upack"
                elif name == "petitepacked":
                    search_name = "petite"
                else:
                    search_name = name
                if search_name.upper() in predicted_packer_name.upper():
                    return name
            return None
