import pygraphviz as pgv

visited = []
name_file = "outputs/fsg_Cacheset.exe_model.dot"
name_file = "outputs/fsg_accesschk.exe_model.dot"
name_file = "outputs/upx_accesschk.exe_model.dot"
name_file = "outputs/packed_unikey32.exe_model.dot"
name_file = "outputs/packed_Cacheset.exe_model.dot"
G = pgv.AGraph("/home/hungpt/workspace/research/oep-detection/utils/{}".format(name_file))
# print(G.nodes())
# print(G.edges())
# print(len(G.nodes()))
# print(len(G.edges()))


class Node:
    def __init__(self, address, opcode):
        self.address = address
        self.opcode = opcode


adj = {}
label = {}


def get_node_information(s):
    if not s.startswith('a0x'):
        address = s
        opcode = "API"
        return address, opcode
    address = s[1:11]
    opcode = s[11:]

    return address, opcode


def get_edge_informaton(p):
    source, target = p
    source, target = get_node_information(source), get_node_information(target)


start_node = -1

for idx, node in enumerate(G.nodes()):
    address, opcode = get_node_information(node)
    if not address in adj:
        adj[address] = []
        label[address] = opcode
    if idx == 0:
        start_node = address

for edge in G.edges():
    source, target = edge
    source, target = get_node_information(source), get_node_information(target)
    if not (target[0] in adj[source[0]]):
        adj[source[0]].append(target[0])


def compare(item1, item2):
    if label[item1] < label[item2]:
        return -1
    elif label[item1] > label[item2]:
        return 1
    else:
        return 0


for key, value in adj.items():
    # value.sort(key=compare)
    value = sorted(value, key=lambda x: label[x])


# print(adj)

def dfs(u):
    global visited
    visited.append(u)
    for v in adj[u]:
        if not v in visited:
            dfs(v)


# dfs(start_node)
# print(visited)
# with open(name_file + ".asm", "w") as f:
#     for node in visited:
#         f.writelines("{}: {}\n".format(node, label[node]))


class BPCFG():
    def __init__(self, dot_file):
        self.G = pgv.AGraph(dot_file)
        self.start_node = -1
        self.adj = {}
        self.label = {}
        for idx, node in enumerate(self.G.nodes()):
            address, opcode = get_node_information(node)
            if not address in self.adj:
                self.adj[address] = []
                self.label[address] = opcode
            if idx == 0:
                self.start_node = address

        for edge in self.G.edges():
            source, target = edge

            source, target = get_node_information(source), get_node_information(target)
            # print("st: {} {}".format(source, target))
            if not (target[0] in self.adj[source[0]]):
                self.adj[source[0]].append(target[0])

    def get_incoming_node(self, node_address):
        print("node_address = {}".format(node_address))
        # print("adj list")
        # print(self.adj)
        results = []
        for key, value in self.adj.items():
            # print("node: {}, adj: {}".format(node, value))
            if node_address in value:
                results.append(key)
        return results
