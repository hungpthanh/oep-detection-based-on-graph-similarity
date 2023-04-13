import os
from collections import Counter

from tqdm import tqdm

from common.models import create_subgraph
from utils.graph_similarity_utils import get_WLK, cosine_similarity
from utils.oep_utils import get_oep_dataset, get_preceding_oep

oep_dictionary = get_oep_dataset()
data_folder_path = "data"


def main():
    packer_names = ["aspack", "upx", "fsg"]
    packer_names = ["aspack"]
    sample_file = "Dbgview.exe"


    for packer_name in packer_names:
        print("packer name: {}".format(packer_name))
        sample_file_path = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                        "{}_{}_model.dot".format(packer_name, sample_file))
        preceding_sample_file = get_preceding_oep(sample_file_path, oep_dictionary[sample_file])
        G1 = create_subgraph(dot_file=os.path.join(sample_file_path),
                             address=preceding_sample_file)
        total_sample = 0
        correct_sample = 0
        for file_name, oep_address in oep_dictionary.items():
            if file_name == sample_file or file_name == "name":
                continue
            if file_name != "Cacheset.exe":
                continue
            try:
                print("File name: {}".format(file_name))
                packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                               "{}_{}_model.dot".format(packer_name, file_name))
                if not os.path.exists(packed_dot_file):
                    continue

                print("packed_dot_file: {}".format(packed_dot_file))
                preceding_oep = get_preceding_oep(packed_dot_file, oep_address)
                node_list = list(create_subgraph(dot_file=packed_dot_file, address="-1",
                                                 from_specific_node=False).nodes)

                node_labels = get_WLK(G1, 2)
                unique_labels = list(node_labels.values())
                data = {'G1': Counter(list(node_labels.values()))}
                print("Generating subgraph of {} nodes:".format(len(node_list)))
                for node in tqdm(node_list):
                    G2 = create_subgraph(dot_file=packed_dot_file, address=node,
                                         from_specific_node=True)
                    node_labels = get_WLK(G2, 2)
                    unique_labels = unique_labels + list(node_labels.values())
                    data[node] = Counter(list(node_labels.values()))

                unique_labels = sorted(list(set(unique_labels)))

                histograms = {}
                for idx, label in tqdm(enumerate(unique_labels)):
                    for name in ['G1'] + node_list:
                        if not (name in histograms):
                            histograms[name] = []
                        if label in data:
                            histograms[name].append(data[name][label])
                        else:
                            histograms[name].append(0)

                best_similarity = 0
                save_address = "-1"
                for name in tqdm(node_list):
                    sim = cosine_similarity(histograms['G1'], histograms[name])
                    if sim > best_similarity:
                        best_similarity = sim
                        save_address = name
                total_sample += 1
                if save_address == preceding_oep:
                    correct_sample += 1
                print("packer: {}, file: {}, preceding_oep: {}, predicted_preceding_oep: {}".format(packer_name,
                                                                                                    file_name,
                                                                                                    preceding_oep,
                                                                                                    save_address))
            except Exception as e:
                print("Error in packer {} of {}: {}".format(packer_name, file_name, e))
                pass
        print("The accuracy of packer: {} is {}".format(packer_name, 1.0 * correct_sample / total_sample))


if __name__ == '__main__':
    main()
