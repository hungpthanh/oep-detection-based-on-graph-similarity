import pandas as pd

log_file = "/media/hungpt/SSD-HUNG/OEP_detection/Experiment BE-PUM/BE_PUM_V2/data/data/techniquesFrequency.txt"


def get_packer_name_and_filename(packer_name_file_name):
    packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
        packer_name_file_name.strip().split("_")[1:])
    return packer_name_of_file, file_name


packer_names = ["upx", "aspack", "packman", "jdpack", "telock", "yodaC", "winupack", "mew", "petitepacked", "pecompact",
                "fsg", "MPRESS"]
set_techniques = {}
set_name = []

def get_average(arr):
    n = len(arr)
    sum_arr = [0] * 14
    for e in arr:
        for idx in range(14):
            sum_arr[idx] += e[idx]
    for idx in range(14):
        sum_arr[int(idx)] = sum_arr[idx] / n
    return sum_arr

with open(log_file, "r") as f:
    lines = []
    for line in f:
        row = line.strip().split("\t")
        lines.append(row)
    for line in lines[::-1]:
        row = line
        name = row[0]
        if name in set_name:
            continue
        set_name.append(name)
        if ("Trojan" in name) or ("Backdoor" in name):
            continue

        # print(name)
        obfuscation_techniques = [int(item) for item in row[2:2 + 14]]
        packer_name, file_name = get_packer_name_and_filename(name)
        if packer_name == "pecompact":
            print("hello pecompact")
        print("{}: {}".format(packer_name, file_name))
        if not (packer_name in set_techniques):
            set_techniques[packer_name] = []
        set_techniques[packer_name].append(obfuscation_techniques)
        # for idx, tq in enumerate(obfuscation_techniques):
        #     if tq > 0:
        #         set_techniques[packer_name].append()
rows = []
for key, value in set_techniques.items():
    # print("key = {}".format(key))
    if key in packer_names:
        # print(get_average(value))
        # print("Key: {}, {}".format(key, get_average(value)))
        print("Key: {}".format(key))
        row = []
        for idx, ele in enumerate(get_average(value)):
            print("({}){:.2f} ".format(idx, ele), end="")
            row.append("{:.2f}".format(ele))
        rows.append(row)
        print()
        # print("Key: {}, {}".format(key, value))
pd.set_option('display.max_columns', None)
df = pd.DataFrame(rows, columns=['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13'],
                  index=["telock", "winupack", "jdpack", "packman", "mew", "yodaC", "petite", "MPRESS", "pecompact", "aspack", "fsg", "upx"])
# print(df)
df.to_csv('file_name.csv')
