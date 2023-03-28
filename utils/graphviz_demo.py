import os
os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin'

from graphviz import Source
path = 'utils/packed_unikey32.exe_model.dot'
s = Source.from_file(path)
s.view()