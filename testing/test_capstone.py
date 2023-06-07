from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone import *
from capstone.x86 import *
import pefile


def test1():
    def disassemble_memory_from_file(file_path, start_address, num_bytes):
        # Initialize Capstone
        md = Cs(CS_ARCH_X86, CS_MODE_32)

        with open(file_path, 'rb') as f:
            # Seek to the start address
            f.seek(start_address)

            # Read the specified number of bytes
            memory_data = f.read(num_bytes)

        # Disassemble the memory
        instructions = []
        for i in md.disasm(memory_data, start_address):
            instructions.append(i)

        return instructions

    file_path = '/home/hungpt/Downloads/upx_AccessEnum_dump2.exe'
    start_address = 0x00407a98
    num_bytes = 16

    instructions = disassemble_memory_from_file(file_path, start_address, num_bytes)

    print("go go")
    # Iterate through the disassembled instructions
    for instruction in instructions:
        print(f"0x{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}")


def test2():
    # https://isleem.medium.com/create-your-own-disassembler-in-python-pefile-capstone-754f863b2e1c
    # the function takes two arguments, both are fetched from the exe file using
    # pefile. the first one is the list of all sections. The second one is the
    # address of the first instruction in the program
    def get_main_code_section(sections, base_of_code):
        addresses = []
        # get addresses of all sections
        for section in sections:
            addresses.append(section.VirtualAddress)

        # if the address of section corresponds to the first instruction then
        # this section should be the main code section
        if base_of_code in addresses:
            return sections[addresses.index(base_of_code)]
        # otherwise, sort addresses and look for the interval to which the base of code
        # belongs
        else:
            addresses.append(base_of_code)
            addresses.sort()
            if addresses.index(base_of_code) != 0:
                return sections[addresses.index(base_of_code) - 1]
            else:
                # this means we failed to locate it
                return None

    def fine_disassemble(exe):
        # get main code section
        main_code = get_main_code_section(exe.sections, exe.OPTIONAL_HEADER.BaseOfCode)
        # define architecutre of the machine
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        last_address = 0
        last_size = 0
        # Beginning of code section
        begin = main_code.PointerToRawData
        # the end of the first continuous bloc of code
        end = begin + main_code.SizeOfRawData
        while True:
            # parse code section and disassemble it
            data = exe.get_memory_mapped_image()[begin:end]
            for i in md.disasm(data, begin):
                print(i)
                last_address = int(i.address)
                last_size = i.size
            # sometimes you need to skip some bytes
            begin = max(int(last_address), begin) + last_size + 1
            if begin >= end:
                print("out")
                break

    exe_file_path = '/home/hungpt/Downloads/upx_AccessEnum_dump2.exe'

    try:
        # parse exe file
        exe = pefile.PE(exe_file_path)
        try:
            # call the function we created earlier
            fine_disassemble(exe)
        except:
            print('something is wrong with this exe file')
    except:
        print('pefile cannot parse this file')


def test3():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32

    # Specify the path to the binary file
    binary_file = "/home/hungpt/Downloads/upx_AccessEnum_dump2.exe"

    # Initialize Capstone
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # Read the binary file into memory
    with open(binary_file, "rb") as f:
        binary_data = f.read()

    # Disassemble instructions
    for insn in md.disasm(binary_data, 0x1000):
        # Access various properties of the disassembled instruction
        print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))


def test4():
    # https://copyprogramming.com/howto/capstone-disassemble-from-binary-file-in-python
    # !/usr/bin/python
    import pefile
    # from capstone import *
    # load the target PE file
    pe = pefile.PE("/home/hungpt/Downloads/upx_AccessEnum_dump.exe")
    # get the address of the program entry point from the program header
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # compute memory address where the entry code will be loaded into memory
    entrypoint_address = entrypoint + pe.OPTIONAL_HEADER.ImageBase
    # get the binary code from the PE file object
    binary_code = pe.get_memory_mapped_image()[entrypoint:entrypoint + 100]
    # initialize disassembler to disassemble 32 bit x86 binary code
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    # disassemble the code
    for instruction in disassembler.disasm(binary_code, entrypoint_address):
        print("%s\t%s" % (instruction.mnemonic, instruction.op_str))


if __name__ == '__main__':
    test4()
