import sys, os
import pickle
import multiprocessing
from utils import *
from asm_types import *

TOOLS = ['retro_sym', 'ramblr', 'ddisasm']

def get_available_tools(pickle_dir, bin_name):
    tools = []
    for tool in TOOLS:
        tool_path = os.path.join(pickle_dir, tool, bin_name + '.p3')
        print(tool_path)
        if not os.path.exists(tool_path):
            print(tool, 'Not Exists')
            continue
        tools.append(tool)
    return tools

def load_gt(pickle_base_dir, bin_name):
    # Load GT
    pickle_gt_path = os.path.join(pickle_base_dir, 'gt', bin_name + '.p3')
    if not os.path.exists(pickle_gt_path):
        print('No gt ' + pickle_gt_path)
        return None
    pickle_gt_f = open(pickle_gt_path, 'rb')
    prog_c = pickle.load(pickle_gt_f)
    pickle_gt_f.close()

    return prog_c

def load_tool(pickle_base_dir, tool, bin_name):
    pickle_tool_path = os.path.join(pickle_base_dir, tool, bin_name + '.p3')
    pickle_tool_f = open(pickle_tool_path, 'rb')
    prog_r = pickle.load(pickle_tool_f)
    pickle_tool_f.close()

    return prog_r

def filter_ins(arch, elf, funcs, addr):
    for saddr, eaddr in funcs:
        if saddr <= addr and addr < eaddr:
            return False

    data = get_bytes(elf, addr, 15)
    cs = get_disassembler(arch)
    ins = list(cs.disasm(data, addr))[0]
    if ins.mnemonic.startswith('mov'):
        op_str = ins.op_str
        operands = op_str.split(', ')
        return operands[0] != operands[1]
    else:
        return True

def load_nofunc(elf, path):
    funcs = set()
    with open(path) as f:
        for line in f.readlines():
            funcs.add(line.strip())
    addrs = []
    symtab = elf.get_section_by_name('.symtab')
    for symb in symtab.iter_symbols():
        if 'FUNC' in symb['st_info']['type']:
            if symb['st_size'] > 0:
                if symb.name in funcs:
                    addrs.append((symb['st_value'], symb['st_value'] + symb['st_size']))

    return addrs

def count_disasm(arch, bin_path, nofunc_path, prog_c, prog_r):
    addrs_c = set(prog_c.Instrs.keys())
    addrs_r = set(prog_r.Instrs.keys())
    tp = addrs_c.intersection(addrs_r)
    fp = addrs_r - addrs_c
    fn = addrs_c - addrs_r
    if len(fp) > 0 or len(fn) > 0:
        elf = load_elf(bin_path)
        funcs = load_nofunc(elf, nofunc_path)
        fp = set(filter(lambda addr: filter_ins(arch, elf, funcs, addr), fp))
        fn = set(filter(lambda addr: filter_ins(arch, elf, funcs, addr), fn))
    return addrs_c, fp, fn

def save_stat(stat_dir, tool, tot, fp, fn):
    stat_file = os.path.join(stat_dir, 'disasm_result_%s' % tool)
    with open(stat_file, 'w') as f:
        f.write('%d,%d,%d\n' % (len(tot), len(fp), len(fn)))
        for addr in fp:
            f.write('FP %x\n' % addr)
        for addr in fn:
            f.write('FN %x\n' % addr)

def test(args):
    bench_dir, pickle_dir, stat_dir, nofunc_dir, options = args
    package, arch, compiler, pie, opt = options
    print(package, arch, compiler, pie, opt)

    base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
    strip_dir = os.path.join(base_dir, 'bin')
    pickle_base_dir = os.path.join(pickle_dir, package, arch, compiler, pie, opt)
    stat_base_dir = os.path.join(stat_dir, package, arch, compiler, pie, opt)
    nofunc_base_dir = os.path.join(nofunc_dir, package, arch, compiler, pie, opt)

    for bin_name in os.listdir(strip_dir):
        stat_dir = os.path.join(stat_base_dir, bin_name)
        os.system('mkdir -p %s' % stat_dir)

        bin_path = os.path.join(strip_dir, bin_name)
        print(bin_name)

        prog_c = load_gt(pickle_base_dir, bin_name)
        if prog_c is None:
            continue

        nofunc_path = os.path.join(nofunc_base_dir, bin_name)
        available_tools = get_available_tools(pickle_base_dir, bin_name)
        if len(available_tools) > 0:

            for tool in available_tools:
                prog_r = load_tool(pickle_base_dir, tool, bin_name)
                tot, fp, fn = count_disasm(arch, bin_path, nofunc_path, prog_c, prog_r)

                save_stat(stat_dir, tool, tot, fp, fn)

def main(bench_dir, pickle_dir, stat_dir, nofunc_dir):
    args = []
    for package, arch, compiler, pie, opt in gen_options():
        args.append((bench_dir, pickle_dir, stat_dir, nofunc_dir, [package, arch, compiler, pie, opt]))
    p = multiprocessing.Pool(84)
    p.map(test, args)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    pickle_dir = sys.argv[2]
    #pickle_dir = '/home/bbbig/tmp/pickles4'
    nofunc_dir = sys.argv[3]
    #nofunc_dir = '/home/bbbig/tmp/nofunc'
    stat_dir = sys.argv[4]
    #stat_dir = '/home/soomink/disasm3'
    main(bench_dir, pickle_dir, stat_dir, nofunc_dir)
