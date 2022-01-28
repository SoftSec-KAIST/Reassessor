import sys, os
from utils import *

ddisasmtp = 0
ddisasmfp = 0
ddisasmfn = 0
ramblrtp = 0
ramblrfp = 0
ramblrfn = 0
retrotp = 0
retrofp = 0
retrofn = 0

retro_fps = set()

def count_ddisasm(stat_base, name):
    global ddisasmtp, ddisasmfp, ddisasmfn
    stat_file = os.path.join(stat_base, name, 'disasm_result_ddisasm')
    if not os.path.exists(stat_file):
        return
    with open(stat_file) as f:
        lines = f.readlines()
        tp, _, _ = lines[0].split(',')
        ddisasmtp += int(tp)
        for line in lines:
            if line.startswith('FP'):
                ddisasmfp += 1
            elif line.startswith('FN'):
                ddisasmfn += 1

def count_retro(stat_base, name):
    global retrotp, retrofp, retrofn
    stat_file = os.path.join(stat_base, name, 'disasm_result_retro_sym')
    if not os.path.exists(stat_file):
        return
    with open(stat_file) as f:
        lines = f.readlines()
        tp, _, _ = lines[0].split(',')
        retrotp += int(tp)
        for line in lines:
            if line.startswith('FP'):
                retrofp += 1
                addr = line.split()[1]
                retro_fps.add((stat_file, addr))
            elif line.startswith('FN'):
                retrofn += 1

def count_ramblr(stat_base, name):
    global ramblrtp, ramblrfp, ramblrfn
    stat_file = os.path.join(stat_base, name, 'disasm_result_ramblr')
    if not os.path.exists(stat_file):
        return
    with open(stat_file) as f:
        lines = f.readlines()
        tp, _, _ = lines[0].split(',')
        ramblrtp += int(tp)
        for line in lines:
            if line.startswith('FP'):
                ramblrfp += 1
            elif line.startswith('FN'):
                ramblrfn += 1

def main(bench_dir, stat_dir):
    for package, arch, compiler, pie, opt in gen_options():
        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        for name in os.listdir(bin_dir):
            count_ddisasm(stat_base, name)
            if arch == 'x64' and pie == 'pie':
                count_retro(stat_base, name)
            if pie == 'nopie':
                count_ramblr(stat_base, name)

    print('Ramblr %d %d %d' % (ramblrtp, ramblrfp, ramblrfn))
    print('Retro %d %d %d' % (retrotp, retrofp, retrofn))
    print('DDisasm %d %d %d' % (ddisasmtp, ddisasmfp, ddisasmfn))

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    stat_dir = sys.argv[2]
    #stat_dir = '/home/soomink/disasm3'
    main(bench_dir, stat_dir)
