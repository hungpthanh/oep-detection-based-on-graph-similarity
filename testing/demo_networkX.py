import networkx as nx
from networkx.drawing.nx_agraph import write_dot, read_dot

from utils.pygraphviz_demmo import get_node_information

G = nx.DiGraph(read_dot(path="data/asm_cfg/upx_accesschk.exe_model.dot"))

print(type(G))


print(G.nodes())
print(G.edges())

# paths = nx.all_simple_paths(G, "a0x00540000movl_0x4001d0UINT32_ebx", "a0x0040c429call_0x414ad4")
# for path in paths:
#     print(path)
def get_opcode(s):
    address, _ = get_node_information(s)
    return _.split("_")[0]


paths = list(nx.shortest_simple_paths(G, "a0x004c4980pusha_", "a0x0040c429call_0x414ad4"))
for path in paths:
    print(len(path))
    path = [get_opcode(s) for s in path]
    print(path)
