import peid
from pefile import PE

file = "/home/hungpt/Desktop/upx_ADInsight.exe.GUnPacker.dump"


# print(peid.find_ep_only_signature(file))
# pe = PE(file)
# ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
# print("ep = {}".format(ep))

def using_pefile():
    import pefile

    pe = pefile.PE(file)
    entry_point_address = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    print("Entry Point Address: 0x{:X}".format(entry_point_address))

def using():
    pass

if __name__ == '__main__':
    using_pefile()

