import os
os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin'

from graphviz import Source
# path = 'utils/aspack_ADInsight.exe_model.dot'
path = 'data/asm_cfg/aspack/aspack_accesschk.exe_model.dot'
s = Source.from_file(path)
s.view()
