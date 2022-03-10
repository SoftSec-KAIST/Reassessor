import sys, os
from utils import *
import roman

class Stat:
    def __init__(self):
        self.ddisasmins = [0, [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]
        self.ddisasmdata = [0, [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]
        self.ramblrins = [0, [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]
        self.ramblrdata = [0 ,[0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]
        self.retroins = [0, [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]
        self.retrodata = [0, [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]

def update_error(stat, tool, sym_ty, ty, err):
    if tool == 'ddisasm':
        if ty == 'Ins':
            if sym_ty == 0:
                stat.ddisasmins[0] += 1
            else:
                if err == 'FP':
                    stat.ddisasmins[sym_ty][0] += 1
                else:
                    stat.ddisasmins[sym_ty][1] += 1
        else:
            if sym_ty == 0:
                stat.ddisasmdata[0] += 1
            else:
                if err == 'FP':
                    stat.ddisasmdata[sym_ty][0] += 1
                else:
                    stat.ddisasmdata[sym_ty][1] += 1
    elif tool == 'ramblr':
        if ty == 'Ins':
            if sym_ty == 0:
                stat.ramblrins[0] += 1
            else:
                if err == 'FP':
                    stat.ramblrins[sym_ty][0] += 1
                else:
                    stat.ramblrins[sym_ty][1] += 1
        else:
            if sym_ty == 0:
                stat.ramblrdata[0] += 1
            else:
                if err == 'FP':
                    stat.ramblrdata[sym_ty][0] += 1
                else:
                    stat.ramblrdata[sym_ty][1] += 1
    elif tool == 'retro_sym':
        if ty == 'Ins':
            if sym_ty == 0:
                stat.retroins[0] += 1
            else:
                if err == 'FP':
                    stat.retroins[sym_ty][0] += 1
                else:
                    stat.retroins[sym_ty][1] += 1
        else:
            if sym_ty == 0:
                stat.retrodata[0] += 1
            else:
                if err == 'FP':
                    stat.retrodata[sym_ty][0] += 1
                else:
                    stat.retrodata[sym_ty][1] += 1

def get_stat(stat, res_file, tool):
    if not os.path.exists(res_file):
        return

    cur_type = -1
    with open(res_file) as f:
        for line in f.readlines():
            line = line.strip()
            if line.startswith('Type'):
                cur_type = roman.fromRoman(line.split()[1])
                if cur_type == 8:
                    cur_type = 0
            elif cur_type == -1:
                continue
            else:
                tokens = line.split()
                ty = tokens[1]
                err = tokens[2]
                if cur_type == 0 and err == 'FN':
                    err = 'FP'
                update_error(stat, tool, cur_type, ty, err)

def save_stat(stat, stat_dir):
    os.system('mkdir -p %s' % stat_dir)
    errname = os.path.join(stat_dir, 'error_count')
    with open(errname, 'w') as f:
        f.write('%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (
            stat.ddisasmins[1][0],
            stat.ddisasmins[1][1],
            stat.ddisasmins[2][0],
            stat.ddisasmins[2][1],
            stat.ddisasmins[3][0],
            stat.ddisasmins[3][1],
            stat.ddisasmins[4][0],
            stat.ddisasmins[4][1],
            stat.ddisasmins[5][0],
            stat.ddisasmins[5][1],
            stat.ddisasmins[6][0],
            stat.ddisasmins[6][1],
            stat.ddisasmins[7][0],
            stat.ddisasmins[7][1],
            stat.ddisasmins[0]
            ))
        f.write('%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (
            stat.ddisasmdata[1][0],
            stat.ddisasmdata[1][1],
            stat.ddisasmdata[2][0],
            stat.ddisasmdata[2][1],
            stat.ddisasmdata[3][0],
            stat.ddisasmdata[3][1],
            stat.ddisasmdata[4][0],
            stat.ddisasmdata[4][1],
            stat.ddisasmdata[5][0],
            stat.ddisasmdata[5][1],
            stat.ddisasmdata[6][0],
            stat.ddisasmdata[6][1],
            stat.ddisasmdata[7][0],
            stat.ddisasmdata[7][1],
            stat.ddisasmdata[0]
            ))
        f.write('%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (
            stat.ramblrins[1][0],
            stat.ramblrins[1][1],
            stat.ramblrins[2][0],
            stat.ramblrins[2][1],
            stat.ramblrins[3][0],
            stat.ramblrins[3][1],
            stat.ramblrins[4][0],
            stat.ramblrins[4][1],
            stat.ramblrins[5][0],
            stat.ramblrins[5][1],
            stat.ramblrins[6][0],
            stat.ramblrins[6][1],
            stat.ramblrins[7][0],
            stat.ramblrins[7][1],
            stat.ramblrins[0]
            ))
        f.write('%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (
            stat.ramblrdata[1][0],
            stat.ramblrdata[1][1],
            stat.ramblrdata[2][0],
            stat.ramblrdata[2][1],
            stat.ramblrdata[3][0],
            stat.ramblrdata[3][1],
            stat.ramblrdata[4][0],
            stat.ramblrdata[4][1],
            stat.ramblrdata[5][0],
            stat.ramblrdata[5][1],
            stat.ramblrdata[6][0],
            stat.ramblrdata[6][1],
            stat.ramblrdata[7][0],
            stat.ramblrdata[7][1],
            stat.ramblrdata[0]
            ))
        f.write('%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (
            stat.retroins[1][0],
            stat.retroins[1][1],
            stat.retroins[2][0],
            stat.retroins[2][1],
            stat.retroins[3][0],
            stat.retroins[3][1],
            stat.retroins[4][0],
            stat.retroins[4][1],
            stat.retroins[5][0],
            stat.retroins[5][1],
            stat.retroins[6][0],
            stat.retroins[6][1],
            stat.retroins[7][0],
            stat.retroins[7][1],
            stat.retroins[0]
            ))
        f.write('%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n' % (
            stat.retrodata[1][0],
            stat.retrodata[1][1],
            stat.retrodata[2][0],
            stat.retrodata[2][1],
            stat.retrodata[3][0],
            stat.retrodata[3][1],
            stat.retrodata[4][0],
            stat.retrodata[4][1],
            stat.retrodata[5][0],
            stat.retrodata[5][1],
            stat.retrodata[6][0],
            stat.retrodata[6][1],
            stat.retrodata[7][0],
            stat.retrodata[7][1],
            stat.retrodata[0]
            ))

def main(bench_dir, res_dir, stat_dir):
    for package, arch, compiler, pie, opt in gen_options():
        print(package, arch, compiler, pie, opt)

        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        res_base = os.path.join(res_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')

        for name in os.listdir(bin_dir):
            stat_path = os.path.join(stat_base, name)
            stat = Stat()

            for tool in ['ddisasm', 'ramblr', 'retro_sym']:
                res_file = os.path.join(res_base, tool, name)
                get_stat(stat, res_file, tool)

            save_stat(stat, stat_path)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    res_dir = sys.argv[2]
    #res_dir = '/home/bbbig/evaluation'
    stat_dir = sys.argv[3]
    #stat_dir = '/home/soomink/stat'
    main(bench_dir, res_dir, stat_dir)
