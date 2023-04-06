from utils.pygraphviz_demmo import BPCFG

name1 = "accesschk"
name2 = "ADExplorer"

dot_file = {}
dot_file[name1] = "utils/outputs/upx_accesschk.exe_model.dot"
dot_file[name2] = "utils/outputs/upx_ADExplorer.exe_model.dot"

cfg = {}
cfg[name1] = BPCFG(dot_file[name1])
cfg[name2] = BPCFG(dot_file[name2])

# print(cfg[name1].adj)
# print(cfg[name1].get_rev_path_from("0x004c4b54"))
cfg[name2].clear_cycle()
print(cfg[name2].get_rev_path_from("0x0047acc4"))
