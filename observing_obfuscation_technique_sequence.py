import os

from utils.oep_utils import get_oep_dataset, get_preceding_oep, get_matched_signature, \
    get_obfuscation_technique_sequence

oep_dictionary = get_oep_dataset()
data_folder_path = "data"


def insert_string(string, added_string, index):
    return string[:index] + added_string + string[index:]


def main():
    packer_names = ["aspack", "fsg", "upx", "MPRESS", "petitepacked"]
    for packer_name in packer_names:
        print("packer name: {}".format(packer_name))
        data = []
        data_by_distance = {}
        for file_name, oep_address in oep_dictionary.items():

            packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                           "{}_{}_model.dot".format(packer_name, file_name))
            packed_log_file = os.path.join(data_folder_path, "logs", packer_name,
                                           "Log-{}_{}.log".format(packer_name, file_name))
            if not os.path.exists(packed_dot_file):
                continue
            end_unpacking_oep = get_preceding_oep(packed_dot_file, oep_address)
            if not end_unpacking_oep:
                continue
            matched_signature = get_matched_signature(packed_log_file)
            if matched_signature is None:
                print("matched is None: {} {}".format(packer_name, file_name))
                continue
            matched_signature = insert_string(get_matched_signature(packed_log_file), "00", 2)
            print("File name: {}, end_unpacking: {}, matched_signature: {}".format(file_name, end_unpacking_oep,
                                                                                   matched_signature))
            # try:
            obfuscation_technique_sequence, obfuscation_technique_address = get_obfuscation_technique_sequence(
                packer_name, file_name)
            end_unpacking_oep_base10 = int(end_unpacking_oep, base=16)
            matched_signature_base10 = int(matched_signature, base=16)
            new_record = {
                'distance': end_unpacking_oep_base10 - matched_signature_base10,
                'packer_name': packer_name,
                'file_name': file_name,
                'obfuscation_technique_sequence': obfuscation_technique_sequence,
                'obfuscation_technique_address': obfuscation_technique_address,
            }
            if new_record['distance'] in data_by_distance:
                data_by_distance[new_record['distance']].append(new_record['obfuscation_technique_sequence'])
            else:
                data_by_distance[new_record['distance']] = [new_record['obfuscation_technique_sequence']]
            data.append(new_record)
            # except Exception as e:
            #     print(e)
            #     pass
        print("packer_name: {}".format(packer_name))
        for record in data:
            print(record)

        for key, values in data_by_distance.items():
            with open("logs/log_obfuscation_technique/{}_{}.txt".format(packer_name, key), "w") as fout:
                values = sorted(values)
                for value in values:
                    fout.writelines(value + "\n")


if __name__ == '__main__':
    main()
