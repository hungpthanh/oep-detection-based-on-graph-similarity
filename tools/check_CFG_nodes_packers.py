from utils.graph_similarity_utils import load_standard_feature

standard_feature = load_standard_feature()


def get_number_of_nodes(template):
    ans = 0
    for node in template.keys():
        if node.startswith("1-") or node.startswith("2-"):
            continue
        ans += 1
    return ans


for key, templates in standard_feature.items():
    print("key = {}".format(key))
    # print(templates)
    for cfg_unpacking_stub in templates.values():
        # print(cfg_unpacking_stub)
        print(get_number_of_nodes(cfg_unpacking_stub))
        # break
    # break
