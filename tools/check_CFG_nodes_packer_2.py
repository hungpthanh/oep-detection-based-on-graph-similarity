import os.path

import networkx as nx
from networkx.drawing.nx_agraph import read_dot

from utils.dataset_utils import get_test_list, get_train_list
from utils.oep_utils import get_oep_dataset_2

test_list = get_train_list() + get_test_list()
data_folder_path = "data"
oep_dictionary_2 = get_oep_dataset_2()

f = open("debug2.txt", "w")

def get_packer_name_and_filename(packer_name_file_name):
    packer_name_of_file, file_name = packer_name_file_name.strip().split("_")[0], "_".join(
        packer_name_file_name.strip().split("_")[1:])
    return packer_name_of_file, file_name


def sort_successor(cfg, u):
    import functools

    def is_instruction(u):
        return str(u).startswith("a")

    new_successors = list(cfg.successors(u)).copy()

    def compare(u, v):
        if is_instruction(u) and is_instruction(v):
            return (u[1:11] < v[1:11]) - (u[1:11] > v[1:11])
        if (not is_instruction(u)) and (not is_instruction(v)):
            return cfg.in_degree(v) - cfg.in_degree(u)
        if (not is_instruction(u)) and (is_instruction(v)):
            return -1
        return 1

    new_successors.sort(key=functools.cmp_to_key(compare))
    return new_successors


def dfs(new_cfg, original_code_cfg, start_node):
    stack = []
    visited = set()
    stack.append(start_node)
    print("start_node = {}".format(start_node))
    f.writelines("start_node = {}".format(start_node))

    node_original = [v for v in original_code_cfg.nodes]
    print("System time: in {}".format("GetSystemTimeAsFileTime_kernel32_dll" in node_original))
    node_new = [v for v in new_cfg.nodes]
    print("node_origina: {}".format(node_original))
    print("len sss: {}".format(len(node_original)))
    print("len sss new: {}".format(len(node_new)))
    while len(stack) > 0:
        u = stack[-1]
        if u == "GetSystemTimeAsFileTime_KERNEL32_DLL":
            print("stack")
            print(stack)
        visited.add(u)
        exist_node = False
        # we need to sort successor here
        next_candidates = sort_successor(new_cfg, u)
        print("u: {}, next = {}, suces of u: {}".format(u, next_candidates, [v for v in new_cfg.successors(u)]))

        f.writelines("u: {}, next = {}, suces of u: {}, next in original program: {}\n".format(u, next_candidates, [v for v in new_cfg.successors(u)], next_candidates in node_original))
        for v in next_candidates:
            if not (v in visited):
                exist_node = True
                stack.append(v)
                break
        if not exist_node:
            stack.pop()
    print("len visit = {}".format(len(visited)))
    return len(visited), visited


def main():
    count_nodes = {}
    count_sample = {}
    for idx, item in enumerate(test_list):
        packer_name, file_name = get_packer_name_and_filename(item)
        # if item != "upx_AccessEnum.exe":
        #     continue
        if packer_name != "upx":
            continue
        print("packer name: {}, file_name: {}".format(packer_name, file_name))
        packed_dot_file = os.path.join(data_folder_path, "asm_cfg", packer_name,
                                       "{}_{}_model.dot".format(packer_name, file_name))
        original_dot_file = os.path.join(data_folder_path, "log_bepum_malware", "{}_model.dot".format(file_name))
        try:
            packed_code_cfg = nx.MultiDiGraph(read_dot(path=packed_dot_file))
            original_code_cfg = nx.DiGraph(read_dot(path=original_dot_file))

            start_node = [v for v in packed_code_cfg.nodes][0]
            len_before, visited_old = dfs(packed_code_cfg, original_code_cfg, start_node)
            oep_address = oep_dictionary_2[item]
            exit_of_unpacking_stubs = [v for v in packed_code_cfg.predecessors(oep_address)][0]
            # print("successor: {}".format([v for v in packed_code_cfg.successors(exit_of_unpacking_stubs)]))
            packed_code_cfg.remove_edge(exit_of_unpacking_stubs, oep_address)
            # print("successor after: {}".format([v for v in packed_code_cfg.successors(exit_of_unpacking_stubs)]))
            print("=" * 15)
            len_after, visited_new = dfs(packed_code_cfg, original_code_cfg, start_node)
            print("oep_address = {}".format(oep_address))
            print("Exit: {}".format(exit_of_unpacking_stubs))
            print("len before {} and len after: {}".format(len_before, len_after))
            print("EEEE: {} - {}".format(len(visited_old), len(set(visited_old))))

            for v in visited_old:
                if v == "a0x004149d8call_0x41f6b3":
                    print("v nay aaaa")
                if not (v in visited_new):
                    print("dont access: {}\n".format(v))
            if not (packer_name in count_nodes):
                count_nodes[packer_name] = 0
                count_sample[packer_name] = 0
            count_nodes[packer_name] += len_after
            count_sample[packer_name] += 1

        except Exception as e:
            print(e)
            pass
        print("pacer file: {} {}".format(packer_name, file_name))
        break
    for key in count_nodes.keys():
        print("packer_name = {}, avg node = {:.2f}".format(key, 1.0 * count_nodes[key] / count_sample[key]))


if __name__ == '__main__':
    main()
