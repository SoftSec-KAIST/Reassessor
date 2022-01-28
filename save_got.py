from utils import *
import os
import pickle

BASE = '/data2/benchmark/'
result = {}
for package, arch, compiler, pie, opt in gen_options():
    opts = '/'.join([package, arch, compiler, pie, opt])
    print(opts)
    opts = os.path.join(BASE, opts) + "/bin/"
    for binname in os.listdir(opts):
        b = os.path.join(opts, binname)
        elf = load_elf(b)
        got = elf.get_section_by_name('.got.plt')
        if not got:
            got = elf.get_section_by_name('.got')
        got_addr = got['sh_addr']
        got_size = got['sh_size']
        result[b] = range(got_addr, got_addr + got_size)

pickle_path = "../got.p3"
with open(pickle_path, "wb") as f:
    pickle.dump(result, f)
