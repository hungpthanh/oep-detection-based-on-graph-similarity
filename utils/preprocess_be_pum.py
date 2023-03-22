import os

log_path = "data/logs"
asm_cfg_path = "data/asm_cfg"


def get_end_of_unpacking(name):
    file = os.path.join(log_path, "Log-" + name + ".log")
    with open(file, "r") as f:
        last_line = f[-1]
        if "Packed Identified" in last_line:
            words = last_line.split(" ")
            for word in words:
                if word.startswith("0x"):
                    end_unpacking_address = word
                    return end_unpacking_address
    return None


def get_OEP_of_UPX(name):
    file = os.path.join(asm_cfg_path, name + "_code.asm")
    with open(file, "r") as f:
        traces = []
        for line in f:
            address, instruction = line.split(":")
            traces.append((address, instruction))
        for idx, trace in enumerate(traces):
            if trace[1] == "popa":
                return traces[idx + 6][0], traces[idx + 7][0]
    return None, None


def update_information_UPX(packed_file_path):
    information = {}
    with open(packed_file_path, "r") as f:
        packed_file = [line.strip() for line in f]

    for name in packed_file:
        previous_OEP, OEP = get_OEP_of_UPX(name)
        if OEP is not None:
            information[name]["previous_OEP"] = previous_OEP
            information[name]["OEP"] = OEP

    for name in packed_file:
        end_unpacking_address = get_end_of_unpacking(name)
        if end_unpacking_address is not None:
            information[name]["end_unpacking"] = end_unpacking_address
    return information
