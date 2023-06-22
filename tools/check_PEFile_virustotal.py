import os.path

import pefile

entry_point_data = {}
for idx in range(1, 5):
    with open("/home/hungpt/workspace/research/oep-detection/logs/entry_point_{}.txt".format(idx), "r") as f:
        for line in f:
            line = line.strip()
            name, add = line.split(",")


            file = os.path.join("/home/hungpt/Downloads/win32exe-20230620T135255Z-001/win32exe", name)
            pe = pefile.PE(file)
            entry_point_address = "0x{:X}".format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            print("{} {} {}".format(name, add, entry_point_address))
            if not (name in entry_point_data):
                entry_point_data[name] = [str(add).upper(), entry_point_address.upper()]
cnt = 0
for name, values in entry_point_data.items():

    print("name: {}, PEFile: {}, VirusToal: {}".format(name, values[0], values[1]))
    if values[0] == values[1]:
        cnt += 1

print("{}/{}".format(cnt, len(entry_point_data)))