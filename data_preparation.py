import argparse
import glob
import os

from utils.oep_utils import get_entry_point_from_pefile, search_entry_point_in_asm, get_oep_dataset, get_preceding_oep
from utils.string_utils import get_file_name_from_log

parser = argparse.ArgumentParser()
parser.add_argument('--packer_names', nargs="+", default=["upx", "aspack"])
parser.add_argument('--data_path', default="data", type=str)
parser.add_argument('--original_folder', default="/home/hungpt/Downloads/PackingData-master/Notpacked", type=str)

# Get the arguments
args = parser.parse_args()
oep_dictionary = get_oep_dataset()

def main():
    for packer_name in args.packer_names:
        print("packer name: {}".format(packer_name))
        log_files = glob.glob(os.path.join(args.data_path, "logs", "{}/*.log".format(packer_name)))

        for log_file in log_files:
            file_name = get_file_name_from_log(log_file)
            print("File name: {}".format(file_name))
            dot_file = os.path.join(args.data_path, "asm_cfg",
                                    "{}/{}_{}_model.dot".format(packer_name, packer_name, file_name))
            asm_file = os.path.join(args.data_path, "asm_cfg",
                                    "{}/{}_{}_code.asm".format(packer_name, packer_name, file_name))
            # if dot file or asm file donot exist => Cancel
            if (not os.path.exists(dot_file)) or (not os.path.exists(asm_file)):
                continue

            # get OEP of the packed code
            original_file = os.path.join(args.original_folder, file_name)
            if os.path.exists(original_file):
                entry_point = get_entry_point_from_pefile(original_file)
                OEP = search_entry_point_in_asm(entry_point, asm_file)
            elif file_name in oep_dictionary:
                OEP = oep_dictionary[file_name]
            else:
                continue

            preceding_oep, msg = get_preceding_oep(dot_file, OEP)
            if not preceding_oep:
                print("Packer: {}, file_name: {}, error: {}".format(packer_name, file_name, msg))
                log_file.writelines("Packer: {}, file_name: {}, error: {}\n".format(packer_name, file_name, msg))
                continue



if __name__ == '__main__':
    main()
