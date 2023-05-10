import argparse
import glob
import os
import sys

from tqdm import tqdm
sys.path.append('.')
os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin'

from graphviz import Source

parser = argparse.ArgumentParser()
parser.add_argument('--mode', default="single", type=str)
parser.add_argument("--packers", nargs="+", default=["upx"])
# parser.add_argument('--packer_name', default="upx", type=str)
parser.add_argument('--file_name', default="accesschk.exe", type=str)
parser.add_argument('--data_folder', default=".", type=str)
# Get the arguments
args = parser.parse_args()


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
    path = os.path.join("logs/log_graph_color/", "colored_{}_{}_model.dot".format(args.packers[0], args.file_name))
    s = Source.from_file(path)
    # s.save(directory="logs/log_graph_color")
    s.render()


if __name__ == '__main__':
    if args.mode == "all":
        generate_graph()
    else:
        generate_single()
