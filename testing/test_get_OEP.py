from utils.oep_utils import get_OEP

packer_name = "petitepacked"
file_name = "dxwebsetup.exe"
end_of_unpacking_address = "0x0104910b"
print(get_OEP(packer_name, file_name, end_of_unpacking_address))