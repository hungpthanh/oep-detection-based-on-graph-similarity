import functools

successors = ["a0x0042a058scasb_es_edi__al", "a0x0042a001pusha_", "GetProcAddress_kernel32_dll", "a0x0042a058scasb_es_edi__al"]


def is_instruction(u):
    return str(u).startswith("a")

def compare(u, v):
    if is_instruction(u) and is_instruction(v):
        return (u[1:11] < v[1:11]) - (u[1:11] > v[1:11])
    if (not is_instruction(u)) and (is_instruction(v)):
        return -1
    return 1

successors.sort(key=functools.cmp_to_key(compare))
print(successors)