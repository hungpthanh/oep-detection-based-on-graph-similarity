import networkx as nx
from networkx.algorithms import isomorphism


def example1():
    # create two directed graphs
    G1 = nx.DiGraph()
    G1.add_node(1, label='A')
    G1.add_node(2, label='B')
    G1.add_edge(1, 2)

    G2 = nx.DiGraph()
    G2.add_node('A', color='red')
    G2.add_node('B', color='blue')
    G2.add_edge('A', 'B')

    # create a DiGraphMatcher object with node_match function that compares 'label' attribute
    matcher = nx.algorithms.isomorphism.DiGraphMatcher(G1, G2, node_match=lambda n1, n2: n1['label'] == n2['color'])

    # check semantic feasibility of matching node 1 in G1 with node 'A' in G2
    print(matcher.semantic_feasibility(1, 'A'))  # prints True

    # check semantic feasibility of matching node 2 in G1 with node 'A' in G2
    print(matcher.semantic_feasibility(2, 'A'))  # prints False

def example2():
    import networkx as nx
    from networkx.algorithms.isomorphism import GraphMatcher

    # create two example directed graphs
    G1 = nx.DiGraph()
    G1.add_nodes_from([1, 2, 3])
    G1.add_edges_from([(1, 2), (2, 3)])

    G2 = nx.DiGraph()
    G2.add_nodes_from(['A', 'B', 'C', 'D'])
    G2.add_edges_from([('A', 'B'), ('B', 'C'), ('B', 'D')])

    # create VF2Matcher object
    matcher = isomorphism.DiGraphMatcher(G1, G2)
    print(GraphMatcher.subgraph_is_isomorphic(G1, G2))
    # is_subgraph_isomorphic = Gr subgraph_is_isomorphic(G1, G2)
    # perform semantic matching
    # print(matcher.is_isomorphic())

    # # print the result
    # print(is_isomorphic)

def example3():
    import networkx as nx

    from pymatching import MaximumCommonInducedSubgraph

    # create two example graphs
    G1 = nx.Graph()
    G1.add_nodes_from([1, 2, 3, 4])
    G1.add_edges_from([(1, 2), (2, 3), (3, 4), (4, 1)])

    G2 = nx.Graph()
    G2.add_nodes_from(['A', 'B', 'C', 'D'])
    G2.add_edges_from([('A', 'B'), ('B', 'C'), ('C', 'D'), ('D', 'A')])

    # create a MaximumCommonInducedSubgraph object
    mcis = MaximumCommonInducedSubgraph()

    # find the maximum common induced subgraph
    mcis_graph = mcis.calculate(G1, G2)

    # print the result
    print(mcis_graph.nodes())
    print(mcis_graph.edges())

example3()

