import glob
import os

from tqdm import tqdm

os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin'

from graphviz import Source
# path = 'utils/aspack_ADInsight.exe_model.dot'
# path = 'utils/colored_aspack_accesschk.exe_model.dot'
# s = Source.from_file(path)
# s.view()

def generate_graph():
    paths = glob.glob("logs/log_graph_color/*.*")
    for path in tqdm(paths):
        s = Source.from_file(path)
        # s.save(directory="logs/log_graph_color")
        s.render()

if __name__ == '__main__':
    generate_graph()