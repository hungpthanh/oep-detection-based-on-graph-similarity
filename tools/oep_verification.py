import os.path

from utils.oep_utils import get_oep_dataset

oep_dictionary = get_oep_dataset()
packers = ["upx", "aspack", "fsg", "mew", "MPRESS", "pecompact", "petitepacked", "winupack", "yodaC"]


def get_asm_code_from(address, file_path):
    asm = []
    pos = None
    with open(file_path, "r") as f:
        lines = [line for line in f]
        for idx, line in enumerate(lines):
            if line.startswith("0x"):
                add = line.strip().split(":")[0]
                if add == address:
                    pos = idx
        if address == -1:
            pos = 0
        if not (pos is None):
            for line in lines[pos:]:
                asm.append(line.upper())
    return asm
    #     # lines = lines[::-1]
    #     for line in lines:
    #         if found:
    #             asm.append(line.upper())
    #         else:
    #             if line.startswith("0x"):
    #                 add = line.strip().split(":")[0]
    #                 if add == address:
    #                     found = True
    #                     asm.append(line.upper())
    # return asm


def check_done(log_file_path):
    with open(log_file_path, "r") as f:
        for line in f:
            if "Packer Identified" in line:
                return True
    return False


def compare(original_asm, packed_asm, top_k=-1):
    if top_k == -1:
        top_k = min(len(original_asm), len(packed_asm))
    # print(len(original_asm))
    # print(len(packed_asm))
    for idx in range(0, top_k):
        if original_asm[idx] != packed_asm[idx]:
            # print("{}, {}".format(original_asm[idx], packed_asm[idx]))
            return False
    return True
    # return original_asm[:top_k] == packed_asm[:top_k]


def search(original_asm, packed_asm, top_k):
    query = original_asm[:top_k]
    for idx in range(0, len(packed_asm) - top_k + 1):
        # print("========")
        # print(query)
        # print(packed_asm[idx: idx + top_k - 1])
        if query == packed_asm[idx: idx + top_k]:
            return True
    return False


def main():
    cnt_files = 0
    cnt_matched = 0
    cnt_empty = 0
    cnt_not_found = 0
    for file_name, oep_address in oep_dictionary.items():
        # if file_name != "grepWin-1.9.0_portable.exe":
        #     continue
        original_asm_path = os.path.join("data/log_bepum_malware", "{}_code.asm".format(file_name))
        if not os.path.exists(original_asm_path):
            print("Dont have original asm of {}".format(file_name))
            continue
        original_asm = get_asm_code_from(-1, original_asm_path)
        for packer in packers:
            packed_code_asm_path = os.path.join("data/asm_cfg/{}".format(packer),
                                                "{}_{}_code.asm".format(packer, file_name))
            if not os.path.exists(packed_code_asm_path):
                continue
            log_file = os.path.join("data/logs/{}".format(packer),
                                    "Log-{}_{}.log".format(packer, file_name))
            if not check_done(log_file):
                continue

            if not os.path.exists(packed_code_asm_path):
                continue
            cnt_files += 1
            packed_code_asm = get_asm_code_from(oep_address, packed_code_asm_path)
            # if len(packed_code_asm) == 0:
            #     cnt_empty += 1
            #     continue
            if not search(original_asm, packed_code_asm, 5):
                cnt_not_found += 1
                continue

            # print("packer name: {}, file: {}".format(packer, file_name))
            if compare(original_asm, packed_code_asm, 5):
                cnt_matched += 1
            else:
                print("Wrong!!! {} {}".format(packer, file_name))
                print("Original ASM")
                print(original_asm[:5])
                print("Packed ASM")
                print(packed_code_asm[:5])
    print("match: {}/{}".format(cnt_matched, cnt_files))
    print("# of empty: {}".format(cnt_not_found))


if __name__ == '__main__':
    main()
    # asm = get_asm_code_from(-1, "data/log_bepum_malware/rrenc.exe_code.asm")
    # print(asm)
