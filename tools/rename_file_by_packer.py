import glob
import os.path

folder_path = "/media/hungpt/SSD-HUNG/win32pack/new_winupack/win32exe"
packer_name = "winupack"
files = glob.glob(folder_path + "/*.exe")
for file in files:
    print("file = {}".format(file))
    name_file = os.path.basename(file)
    print("name file: {}".format(name_file))
    new_name_file = "{}_{}".format(packer_name, name_file)
    print("new name file: {}".format(new_name_file))
    new_path = os.path.join(folder_path, new_name_file)
    os.rename(file, new_path)
