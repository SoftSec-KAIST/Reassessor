import sys, os
import pickle
import multiprocessing
from utils import *
from asm_types import *

class DisassemblyStat:
    def __init__(self):
        self.ddisasm = [0, 0, 0]
        self.ramblr = [0, 0, 0]
        self.retro = [0, 0, 0]

class TypeStat:
    def __init__(self):
        self.gtins = [0, 0, 0, 0, 0, 0, 0]
        self.gtdata = [0, 0, 0, 0, 0, 0, 0]
        self.ddisasmins = [0, 0, 0, 0, 0, 0, 0]
        self.ddisasminstarget = [0, 0, 0, 0, 0, 0, 0]
        self.ddisasmdata = [0, 0, 0, 0, 0, 0, 0]
        self.ramblrins = [0, 0, 0, 0, 0, 0, 0]
        self.ramblrinstarget = [0, 0, 0, 0, 0, 0, 0]
        self.ramblrdata = [0, 0, 0, 0, 0, 0, 0]
        self.retroins = [0, 0, 0, 0, 0, 0, 0]
        self.retroinstarget = [0, 0, 0, 0, 0, 0, 0]
        self.retrodata = [0, 0, 0, 0, 0, 0, 0]

def update_symbol(stat, tool, ty, idx, in_intersect):
    if tool == 'gt':
        if ty == 'ins':
            stat.gtins[idx-1] += 1
        else:
            stat.gtdata[idx-1] += 1
    elif tool == 'ddisasm':
        if ty == 'ins':
            if in_intersect:
                stat.ddisasminstarget[idx-1] += 1
            stat.ddisasmins[idx-1] += 1
        else:
            stat.ddisasmdata[idx-1] += 1
    elif tool == 'ramblr':
        if ty == 'ins':
            if in_intersect:
                stat.ramblrinstarget[idx-1] += 1
            stat.ramblrins[idx-1] += 1
        else:
            stat.ramblrdata[idx-1] += 1
    elif tool == 'retro_sym':
        if ty == 'ins':
            if in_intersect:
                stat.retroinstarget[idx-1] += 1
            stat.retroins[idx-1] += 1
        else:
            stat.retrodata[idx-1] += 1

def count_cmpt_symbol(stat, cmpt, tool, ty, in_intersect):
    if cmpt.is_ms():
        if cmpt.is_composite(): # Type II, IV, VI, VII
            if cmpt.Ty == CmptTy.ABSOLUTE: # Type II
                update_symbol(stat, tool, ty, 2, in_intersect)
            elif cmpt.Ty == CmptTy.PCREL: # Type IV
                update_symbol(stat, tool, ty, 4, in_intersect)
            elif cmpt.Ty == CmptTy.GOTOFF: # Type VI
                update_symbol(stat, tool, ty, 6, in_intersect)
            elif cmpt.Ty == CmptTy.OBJREL: # Type VII
                update_symbol(stat, tool, ty, 7, in_intersect)
        else: # Type I, III, V
            if cmpt.Ty == CmptTy.ABSOLUTE: # Type I
                update_symbol(stat, tool, ty, 1, in_intersect)
            elif cmpt.Ty == CmptTy.PCREL: # Type III
                update_symbol(stat, tool, ty, 3, in_intersect)
            elif cmpt.Ty == CmptTy.GOTOFF: # Type V
                update_symbol(stat, tool, ty, 5, in_intersect)

def count_symbols(stat, prog_c, prog_r, tool):
    for addr in prog_r.Instrs:
        ins_r = prog_r.Instrs[addr]
        for idx in ins_r.get_components():
            cmpt = ins_r.Components[idx]
            if addr in prog_c.Instrs:
                ins_c = prog_c.Instrs[addr]
                count_cmpt_symbol(stat, cmpt, tool, 'ins', idx in ins_c.get_components())
            else:
                count_cmpt_symbol(stat, cmpt, tool, 'ins', False)
    for addr in prog_r.Data:
        data = prog_r.Data[addr]
        cmpt = data.Component
        count_cmpt_symbol(stat, cmpt, tool, 'data', True)

def count_disasm(stat, prog_c, prog_r, tool):
    addrs_c = set(prog_c.Instrs.keys())
    addrs_r = set(prog_r.Instrs.keys())
    tp = addrs_c.intersection(addrs_r)
    fp = addrs_r - addrs_c
    fn = addrs_c - addrs_r
    if tool == 'ddisasm':
        stat.ddisasm[0] += len(tp)
        stat.ddisasm[1] += len(fp)
        stat.ddisasm[2] += len(fn)
    elif tool == 'ramblr':
        stat.ramblr[0] += len(tp)
        stat.ramblr[1] += len(fp)
        stat.ramblr[2] += len(fn)
    elif tool == 'retro_sym':
        stat.retro[0] += len(tp)
        stat.retro[1] += len(fp)
        stat.retro[2] += len(fn)

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

def save_stat(disstat, tystat, stat_dir):
    disname = os.path.join(stat_dir, 'disasm_count')
    with open(disname, 'w') as f:
        f.write('%d,%d,%d\n' % tuple(disstat.ddisasm))
        f.write('%d,%d,%d\n' % tuple(disstat.ramblr))
        f.write('%d,%d,%d\n' % tuple(disstat.retro))

    tyname = os.path.join(stat_dir, 'type_count')
    with open(tyname, 'w') as f:
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.gtins))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.gtdata))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.ddisasmins))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.ddisasminstarget))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.ddisasmdata))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.ramblrins))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.ramblrinstarget))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.ramblrdata))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.retroins))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.retroinstarget))
        f.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(tystat.retrodata))

def test(args):
    bench_dir, pickle_dir, stat_dir, options = args
    package, arch, compiler, pie, opt = options
    print(package, arch, compiler, pie, opt)

    base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
    strip_dir = os.path.join(base_dir, 'stripbin')
    pickle_base_dir = os.path.join(pickle_dir, package, arch, compiler, pie, opt)
    stat_base_dir = os.path.join(stat_dir, package, arch, compiler, pie, opt)

    for bin_name in os.listdir(strip_dir):
        stat_dir = os.path.join(stat_base_dir, bin_name)
        os.system('mkdir -p %s' % stat_dir)

        bin_path = os.path.join(strip_dir, bin_name)
        print(bin_name)

        disstat = DisassemblyStat()
        tystat = TypeStat()

        prog_c = load_gt(pickle_base_dir, bin_name)
        if prog_c is None:
            continue
        count_symbols(tystat, prog_c, prog_c, 'gt')

        available_tools = get_available_tools(pickle_base_dir, bin_name)
        if len(available_tools) > 0:

            for tool in available_tools:
                prog_r = load_tool(pickle_base_dir, tool, bin_name)
                count_symbols(tystat, prog_c, prog_r, tool)
                count_disasm(disstat, prog_c, prog_r, tool)

        save_stat(disstat, tystat, stat_dir)

def main(bench_dir, pickle_dir, stat_dir):
    args = []
    for package, arch, compiler, pie, opt in gen_options():
        args.append((bench_dir, pickle_dir, stat_dir, [package, arch, compiler, pie, opt]))
    p = multiprocessing.Pool(84)
    p.map(test, args)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    pickle_dir = sys.argv[2]
    #pickle_dir = '/home/bbbig/tmp/pickles3'
    stat_dir = sys.argv[3]
    #stat_dir = '/home/soomink/stat'
    main(bench_dir, pickle_dir, stat_dir)
