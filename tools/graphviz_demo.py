import argparse
import glob
import os
import sys
sys.path.append('.')
import networkx as nx
from tqdm import tqdm

from utils.graph_utils import create_subgraph
from utils.oep_utils import get_preceding_oep, get_oep_dataset

sys.path.append('.')
os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin'

from graphviz import Source

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="single_unpacking", type=str)
parser.add_argument("--packers", nargs="+", default=["upx"])
# parser.add_argument('--packer_name', default="upx", type=str)
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--data_folder', default=".", type=str)
# Get the arguments
args = parser.parse_args()

data_folder_path = "data"
oep_dictionary = get_oep_dataset()


# path = 'utils/aspack_ADInsight.exe_model.dot'
# path = 'utils/colored_aspack_accesschk.exe_model.dot'
# s = Source.from_file(path)
# s.view()

def generate_graph():
    paths = glob.glob(args.data_folder + "/*.*")
    # print(args.packers)
    # for packer in args.packers:
    #     paths = glob.glob("logs/log_graph_color/colored_{}*".format(packer))
    for path in tqdm(paths):
        if path[-3:] == "dot":
            s = Source.from_file(path)
            # s.save(directory="logs/log_graph_color")
            s.render()


def generate_single():
    # path = os.path.join("logs/log_graph_color/", "colored_{}_{}_model.dot".format(args.packers[0], args.file_name))
    path = os.path.join("data/asm_cfg/{}/".format(args.packers[0]), "{}_{}_model.dot".format(args.packers[0], args.file_name))
    s = Source.from_file(path)
    # s.save(directory="logs/log_graph_color")
    s.render()


def generate_subgraph():
    sample_file = os.path.join("logs/log_graph_color/",
                               "colored_{}_{}_model.dot".format(args.packers[0], args.file_name))
    sample_file_path = os.path.join(data_folder_path, "asm_cfg", args.packers[0],
                                    "{}_{}_model.dot".format(args.packers[0], args.file_name))
    preceding_sample_file, msg = get_preceding_oep(sample_file_path, oep_dictionary[args.file_name])
    G1 = create_subgraph(dot_file=os.path.join(sample_file_path),
                         address=preceding_sample_file, from_specific_node=True, label_with_address=True)
    path = "logs/log_subgraph/end_unpacking_{}_{}.dot".format(args.packers[0], args.file_name)
    nx.nx_agraph.write_dot(G1, path)
    s = Source.from_file(path)
    # s.save(directory="logs/log_graph_color")
    s.render()


if __name__ == '__main__':
    # if args.mode == "all":
    #     generate_graph()
    # elif args.mode == "single":
    #     generate_single()
    # else:
    #     generate_subgraph()

    path = "/home/hungpt/workspace/research/oep-detection/data/log_bepum_malware/Tcpview.exe_model.dot"
    s = Source.from_file(path)
    # s.save(directory="logs/log_graph_color")
    s.render()