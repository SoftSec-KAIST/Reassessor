import os, sys
from enum import Enum
from functools import reduce
from utils import *
from asm_types import *
import match_retro
import match_ramblr
import match_ddisasm
import match_gt
import pickle as pickle
import traceback

TOOLS = ['retro', 'ramblr', 'ddisasm']
TOOLS += ['retro_sym', 'ramblr_sym', 'ddisasm_tym']

def load_gt(bench_dir, match_dir, bin_path, composite_path):
    prog = match_gt.main(bench_dir, bin_path, match_dir, composite_path)
    return prog

def load_tool(tool, asm_path, bin_path):
    if tool.startswith('retro'):
        prog, elf, cs = match_retro.gen_prog(bin_path)
        match_retro.parse_source(prog, elf, cs, asm_path)
        return prog
    elif tool.startswith('ramblr'):
        prog, elf, cs = match_ramblr.gen_prog(bin_path)
        match_ramblr.parse_source(prog, elf, cs, asm_path)
        return prog
    elif tool.startswith('ddisasm'):
        prog, elf, cs, main_addr = match_ddisasm.gen_prog(bin_path)
        match_ddisasm.parse_source(prog, elf, cs, asm_path, main_addr)
        return prog
    else:
        # FIXME
        return None

def save_gt(bench_dir, match_dir, result_dir, prefix, composite_path):
        package, arch, compiler, pie, opt = prefix
        base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(base_dir, 'reloc')
        match_base = os.path.join(match_dir, package, arch, compiler, pie, opt)
        for bin_name in os.listdir(bin_dir):
            try:
                pickle_dir = os.path.join(result_dir, package, arch, compiler, pie, opt, "gt")
                pickle_path = os.path.join(pickle_dir, bin_name + ".p3")
                if os.path.exists(pickle_path):
                    continue
                print(pickle_path)
                bin_path = os.path.join(bin_dir, bin_name)
                match_path = os.path.join(match_base, bin_name + ".json")
                prog_c = load_gt(bench_dir, match_path, bin_path, composite_path)
                os.system("mkdir -p %s" % pickle_dir)
                with open(pickle_path, "wb") as f:
                    pickle.dump(prog_c, f)
            except Exception as e:
                traceback.print_exc(file = sys.stdout)
                pass

def save_tool(bench_dir, result_dir, tool, prefix, reassem_path):
        package, arch, compiler, pie, opt = prefix
        base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        strip_dir = os.path.join(base_dir, 'stripbin')
        bin_dir = os.path.join(base_dir, 'bin')

        reassem_dir = os.path.join(reassem_path, package, arch, compiler, pie, opt)
        for bin_name in os.listdir(bin_dir):
            try:
                bin_path = os.path.join(bin_dir, bin_name)
                strip_path = os.path.join(strip_dir, bin_name)
                #tool_asm = os.path.join(base_dir, tool, bin_name + '.s')
                tool_asm = os.path.join(reassem_dir, tool, bin_name + '.s')
                if not os.path.exists(tool_asm):
                    #print(tool_asm, 'Not Exists')
                    continue
                size = os.path.getsize(tool_asm)
                #if size <= 1024 * 1024 * 1024:
                #    continue
                if size == 0:
                    #print(tool, '0 size')
                    continue
                if size > 1024 * 1024 * 1024:
                    print(tool, 'big size')
                    continue
                prog_r = load_tool(tool, tool_asm, strip_path)
                pickle_dir = os.path.join(result_dir, package, arch, compiler, pie, opt, tool)
                os.system("mkdir -p %s" % pickle_dir)
                pickle_path = os.path.join(pickle_dir, bin_name + ".p3")
                with open(pickle_path, "wb") as f:
                    pickle.dump(prog_r, f)
            except Exception as e:
                traceback.print_exc(file = sys.stdout)
                pass

def main(bench_dir, match_dir, result_dir, mode, prefix, composite_path, reassem_path):
    if mode == "gt":
        save_gt(bench_dir, match_dir, result_dir, prefix, composite_path)
    else:
        save_tool(bench_dir, result_dir, mode, prefix, reassem_path)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    match_dir = sys.argv[2]
    result_dir = sys.argv[3]
    # target in ["gt", "retro", "ramblr", "ddisasm"]
    mode = sys.argv[4]
    # prefix : package, arch, compiler, pie, opt
    prefix = sys.argv[5:10]
    composite_path = sys.argv[10]
    reassem_path = sys.argv[11]
    main(bench_dir, match_dir, result_dir, mode, prefix, composite_path, reassem_path)
