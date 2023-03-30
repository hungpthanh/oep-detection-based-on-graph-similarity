import os
os.environ["PATH"] += os.pathsep + 'C:/Program Files/Graphviz/bin'

from graphviz import Source
path = 'utils/upx_ADExplorer.exe_model.dot'
s = Source.from_file(path)
s.view()

# import pydotplus
# from sklearn import tree
#
# # Data Collection
# X = [[180, 15, 0],
#      [177, 42, 0],
#      [136, 35, 1],
#      [174, 65, 0],
#      [141, 28, 1]]
#
# Y = ['1', '2', '1', '2', '1']
#
# data_feature_names = ['a', 'b', 'c']
#
# # Training
# clf = tree.DecisionTreeClassifier()
# clf = clf.fit(X, Y)
#
# dot_data = tree.export_graphviz(clf,
#                                 feature_names=data_feature_names,
#                                 out_file=None,
#                                 filled=True,
#                                 rounded=True)
# graph = pydotplus.graph_from_dot_data(dot_data)
# graph = pydotplus.graph_from_dot_file("/home/hungpt/workspace/research/oep-detection/utils/fsg_accesschk.exe_model.dot")
# # print(graph.to_string())
#
# for node in graph.get_nodes():
#     print("Node:")
#     print(node.get_name())
#     # print(node.get_port())
#     print(node.to_string())
#     print(node.obj_dict)
#
# # for edge in graph.get_edges():
# #     print(edge.get_source())
# #     print(edge.get_destination())
# #     print(edge.to_string())
# #     print(edge.obj_dict)