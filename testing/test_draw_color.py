import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_pydot import read_dot


def example1():
    # Create a graph with labeled nodes
    G = nx.Graph()
    G.add_nodes_from([1, 2, 3])
    nx.set_node_attributes(G, {1: 'red', 2: 'blue', 3: 'green'}, 'color')

    # Create a dictionary to map node labels to colors
    color_map = {'red': 'r', 'blue': 'b', 'green': 'g'}

    # Create a list of colors for each node based on the label
    node_colors = [color_map[G.nodes[node]['color']] for node in G.nodes()]

    # Draw the graph with nodes colored by their labels
    nx.draw(G, with_labels=True, node_color=node_colors)

    # Display the graph
    plt.show()


def example2():
    G = nx.DiGraph(read_dot(path="utils/outputs/upx_accesschk.exe_model.dot"))
    print(G.nodes)
    node = "a0x004c4b46popa_"
    G.nodes[node]['color'] = 'red'
    nx.nx_agraph.write_dot(G, "demo_color_graph.dot")

    # import networkx as nx
    # from networkx.drawing.nx_agraph import to_agraph
    #
    # G = nx.Graph()
    #
    # G.add_node(1, color='red', style='filled', fillcolor='blue', shape='square')
    # G.add_node(2, color='blue', style='filled')
    # G.add_edge(1, 2, color='green')
    # G.nodes[2]['shape'] = 'circle'
    # G.nodes[2]['fillcolor'] = 'red'
    #
    # A = to_agraph(G)
    # A.layout()
    # A.draw('color.png')
    # print(A.to_string())


if __name__ == '__main__':
    example2()
