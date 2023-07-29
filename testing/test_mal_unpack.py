import malunpack

timeout = 3000 # default 2000
dump_dir = "temp/dumps"

#sample_unpack = malunpack.MalUnpack("../../sample.exe", timeout, dump_dir)

sample_unpack = malunpack.MalUnpack("sample.exe")

# Run Mal Unpack and get the JSON result from the dump folder specified
scan, dump = sample_unpack.unpack_file()

print(scan)
print(dump)