import sys, os
from utils import *
import roman

def main(bench_dir, stat_dir):
    ddisasmins = {
            'x86pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x86nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            }
    ddisasmdata = {
            'x86pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x86nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            }
    ramblrins = {
            'x86pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x86nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            }
    ramblrdata = {
            'x86pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x86nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            }
    retroins = {
            'x86pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x86nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            }
    retrodata = {
            'x86pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64pie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x86nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            'x64nopie': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            }

    ddisasm_fp = 0
    ddisasm_fn = 0
    ramblr_fp = 0
    ramblr_fn = 0
    retro_fp = 0
    retro_fn = 0

    for package, arch, compiler, pie, opt in gen_options():
        #print(package, arch, compiler, pie, opt)
        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        for name in os.listdir(bin_dir):
            stat_file = os.path.join(stat_base, name, 'error_count')
            if not os.path.exists(stat_file):
                continue
            with open(stat_file) as f:
                lines = f.readlines()
            lines = list(map(lambda x: x.strip(), lines))
            ddisasmi = list(map(int, lines[0].split(',')))
            for i in range(15):
                if i % 2 == 0:
                    ddisasm_fp += ddisasmi[i]
                else:
                    ddisasm_fn += ddisasmi[i]
                ddisasmins[arch+pie][i] += ddisasmi[i]
            ddisasmd = list(map(int, lines[1].split(',')))
            for i in range(15):
                if i % 2 == 0:
                    ddisasm_fp += ddisasmd[i]
                else:
                    ddisasm_fn += ddisasmd[i]
                ddisasmdata[arch+pie][i] += ddisasmd[i]
            ramblri = list(map(int, lines[2].split(',')))
            for i in range(15):
                if i % 2 == 0:
                    ramblr_fp += ramblri[i]
                else:
                    ramblr_fn += ramblri[i]
                ramblrins[arch+pie][i] += ramblri[i]
            ramblrd = list(map(int, lines[3].split(',')))
            for i in range(15):
                if i % 2 == 0:
                    ramblr_fp += ramblrd[i]
                else:
                    ramblr_fn += ramblrd[i]
                ramblrdata[arch+pie][i] += ramblrd[i]
            retroi = list(map(int, lines[4].split(',')))
            for i in range(15):
                if i % 2 == 0:
                    retro_fp += retroi[i]
                else:
                    retro_fn += retroi[i]
                retroins[arch+pie][i] += retroi[i]
            retrod = list(map(int, lines[5].split(',')))
            for i in range(15):
                if i % 2 == 0:
                    retro_fp += retrod[i]
                else:
                    retro_fn += retrod[i]
                retrodata[arch+pie][i] += retrod[i]
    for arch in ['x86', 'x64']:
        for pie in ['pie', 'nopie']:
            print(arch + ' - ' + pie)
            for i in range(7):
                print('| Type %s | %d / %d | %d / %d | %d / %d | %d / %d | %d / %d | %d / %d |' % (
                    roman.toRoman(i + 1).upper(),
                    ddisasmins[arch+pie][2*i],
                    ddisasmdata[arch+pie][2*i],
                    ddisasmins[arch+pie][2*i+1],
                    ddisasmdata[arch+pie][2*i+1],
                    ramblrins[arch+pie][2*i],
                    ramblrdata[arch+pie][2*i],
                    ramblrins[arch+pie][2*i+1],
                    ramblrdata[arch+pie][2*i+1],
                    retroins[arch+pie][2*i],
                    retrodata[arch+pie][2*i],
                    retroins[arch+pie][2*i+1],
                    retrodata[arch+pie][2*i+1]
                    ))
                print('%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d' % (
                    ddisasmins[arch+pie][2*i],
                    ddisasmdata[arch+pie][2*i],
                    ddisasmins[arch+pie][2*i+1],
                    ddisasmdata[arch+pie][2*i+1],
                    ramblrins[arch+pie][2*i],
                    ramblrdata[arch+pie][2*i],
                    ramblrins[arch+pie][2*i+1],
                    ramblrdata[arch+pie][2*i+1],
                    retroins[arch+pie][2*i],
                    retrodata[arch+pie][2*i],
                    retroins[arch+pie][2*i+1],
                    retrodata[arch+pie][2*i+1]
                    ))
            print('| Constant | %d / %d | - | %d / %d | - | %d / %d | - |' % (
                ddisasmins[arch+pie][14],
                ddisasmdata[arch+pie][14],
                ramblrins[arch+pie][14],
                ramblrdata[arch+pie][14],
                retroins[arch+pie][14],
                retrodata[arch+pie][14],
                ))
    print(ramblr_fp, ramblr_fn, retro_fp, retro_fn, ddisasm_fp, ddisasm_fn)


if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    stat_dir = sys.argv[2]
    #stat_dir = '/home/soomink/stat'
    main(bench_dir, stat_dir)
