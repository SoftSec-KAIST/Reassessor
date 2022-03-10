import sys, os
from utils import *

def main(bench_dir, stat_dir):
    ddisasmtp = {}
    ddisasmfp = {}
    ddisasmfn = {}
    ramblrtp = {}
    ramblrfp = {}
    ramblrfn = {}
    retrotp = {}
    retrofp = {}
    retrofn = {}
    numddisasm = 0
    numramblr = 0
    numretro = 0

    for package, arch, compiler, pie, opt in gen_options():
        if package not in ddisasmtp:
            ddisasmtp[package] = 0
        if package not in ddisasmfp:
            ddisasmfp[package] = 0
        if package not in ddisasmfn:
            ddisasmfn[package] = 0
        if package not in ramblrtp:
            ramblrtp[package] = 0
        if package not in ramblrfp:
            ramblrfp[package] = 0
        if package not in ramblrfn:
            ramblrfn[package] = 0
        if package not in retrotp:
            retrotp[package] = 0
        if package not in retrofp:
            retrofp[package] = 0
        if package not in retrofn:
            retrofn[package] = 0
        if arch not in ddisasmtp:
            ddisasmtp[arch] = 0
        if arch not in ddisasmfp:
            ddisasmfp[arch] = 0
        if arch not in ddisasmfn:
            ddisasmfn[arch] = 0
        if arch not in ramblrtp:
            ramblrtp[arch] = 0
        if arch not in ramblrfp:
            ramblrfp[arch] = 0
        if arch not in ramblrfn:
            ramblrfn[arch] = 0
        if arch not in retrotp:
            retrotp[arch] = 0
        if arch not in retrofp:
            retrofp[arch] = 0
        if arch not in retrofn:
            retrofn[arch] = 0
        if compiler not in ddisasmtp:
            ddisasmtp[compiler] = 0
        if compiler not in ddisasmfp:
            ddisasmfp[compiler] = 0
        if compiler not in ddisasmfn:
            ddisasmfn[compiler] = 0
        if compiler not in ramblrtp:
            ramblrtp[compiler] = 0
        if compiler not in ramblrfp:
            ramblrfp[compiler] = 0
        if compiler not in ramblrfn:
            ramblrfn[compiler] = 0
        if compiler not in retrotp:
            retrotp[compiler] = 0
        if compiler not in retrofp:
            retrofp[compiler] = 0
        if compiler not in retrofn:
            retrofn[compiler] = 0
        if pie not in ddisasmtp:
            ddisasmtp[pie] = 0
        if pie not in ddisasmfp:
            ddisasmfp[pie] = 0
        if pie not in ddisasmfn:
            ddisasmfn[pie] = 0
        if pie not in ramblrtp:
            ramblrtp[pie] = 0
        if pie not in ramblrfp:
            ramblrfp[pie] = 0
        if pie not in ramblrfn:
            ramblrfn[pie] = 0
        if pie not in retrotp:
            retrotp[pie] = 0
        if pie not in retrofp:
            retrofp[pie] = 0
        if pie not in retrofn:
            retrofn[pie] = 0
        opti, linker = opt.split('-')
        if opti not in ddisasmtp:
            ddisasmtp[opti] = 0
        if opti not in ddisasmfp:
            ddisasmfp[opti] = 0
        if opti not in ddisasmfn:
            ddisasmfn[opti] = 0
        if opti not in ramblrtp:
            ramblrtp[opti] = 0
        if opti not in ramblrfp:
            ramblrfp[opti] = 0
        if opti not in ramblrfn:
            ramblrfn[opti] = 0
        if opti not in retrotp:
            retrotp[opti] = 0
        if opti not in retrofp:
            retrofp[opti] = 0
        if opti not in retrofn:
            retrofn[opti] = 0
        if linker not in ddisasmtp:
            ddisasmtp[linker] = 0
        if linker not in ddisasmfp:
            ddisasmfp[linker] = 0
        if linker not in ddisasmfn:
            ddisasmfn[linker] = 0
        if linker not in ramblrtp:
            ramblrtp[linker] = 0
        if linker not in ramblrfp:
            ramblrfp[linker] = 0
        if linker not in ramblrfn:
            ramblrfn[linker] = 0
        if linker not in retrotp:
            retrotp[linker] = 0
        if linker not in retrofp:
            retrofp[linker] = 0
        if linker not in retrofn:
            retrofn[linker] = 0
        #print(package, arch, compiler, pie, opt)
        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        for name in os.listdir(bin_dir):
            stat_file = os.path.join(stat_base, name, 'disasm_count')
            if not os.path.exists(stat_file):
                continue
            with open(stat_file) as f:
                lines = f.readlines()
            lines = list(map(lambda x: x.strip(), lines))
            ddisasm = list(map(int, lines[0].split(',')))
            ddisasmtp[package] += ddisasm[0]
            ddisasmtp[arch] += ddisasm[0]
            ddisasmtp[compiler] += ddisasm[0]
            ddisasmtp[pie] += ddisasm[0]
            ddisasmtp[opti] += ddisasm[0]
            ddisasmtp[linker] += ddisasm[0]
            ddisasmfp[package] += ddisasm[1]
            ddisasmfp[arch] += ddisasm[1]
            ddisasmfp[compiler] += ddisasm[1]
            ddisasmfp[pie] += ddisasm[1]
            ddisasmfp[opti] += ddisasm[1]
            ddisasmfp[linker] += ddisasm[1]
            ddisasmfn[package] += ddisasm[2]
            ddisasmfn[arch] += ddisasm[2]
            ddisasmfn[compiler] += ddisasm[2]
            ddisasmfn[pie] += ddisasm[2]
            ddisasmfn[opti] += ddisasm[2]
            ddisasmfn[linker] += ddisasm[2]
            if ddisasm[1] + ddisasm[2] > 0:
                numddisasm += 1
            ramblr = list(map(int, lines[1].split(',')))
            ramblrtp[package] += ramblr[0]
            ramblrtp[arch] += ramblr[0]
            ramblrtp[compiler] += ramblr[0]
            ramblrtp[pie] += ramblr[0]
            ramblrtp[opti] += ramblr[0]
            ramblrtp[linker] += ramblr[0]
            ramblrfp[package] += ramblr[1]
            ramblrfp[arch] += ramblr[1]
            ramblrfp[compiler] += ramblr[1]
            ramblrfp[pie] += ramblr[1]
            ramblrfp[opti] += ramblr[1]
            ramblrfp[linker] += ramblr[1]
            ramblrfn[package] += ramblr[2]
            ramblrfn[arch] += ramblr[2]
            ramblrfn[compiler] += ramblr[2]
            ramblrfn[pie] += ramblr[2]
            ramblrfn[opti] += ramblr[2]
            ramblrfn[linker] += ramblr[2]
            if ramblr[1] + ramblr[2] > 0:
                numramblr += 1
            retro = list(map(int, lines[2].split(',')))
            retrotp[package] += retro[0]
            retrotp[arch] += retro[0]
            retrotp[compiler] += retro[0]
            retrotp[pie] += retro[0]
            retrotp[opti] += retro[0]
            retrotp[linker] += retro[0]
            retrofp[package] += retro[1]
            retrofp[arch] += retro[1]
            retrofp[compiler] += retro[1]
            retrofp[pie] += retro[1]
            retrofp[opti] += retro[1]
            retrofp[linker] += retro[1]
            retrofn[package] += retro[2]
            retrofn[arch] += retro[2]
            retrofn[compiler] += retro[2]
            retrofn[pie] += retro[2]
            retrofn[opti] += retro[2]
            retrofn[linker] += retro[2]
            if retro[1] + retro[2] > 0:
                numretro += 1

    for package in PACKAGES:
        print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
            package,
            ramblrtp[package],
            ramblrfp[package],
            ramblrfn[package],
            retrotp[package],
            retrofp[package],
            retrofn[package],
            ddisasmtp[package],
            ddisasmfp[package],
            ddisasmfn[package]))
    for package in PACKAGES:
        print('| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |' % (
            package,
            ramblrtp[package] / (ramblrtp[package] + ramblrfp[package]),
            ramblrtp[package] / (ramblrtp[package] + ramblrfn[package]),
            retrotp[package] / (retrotp[package] + retrofp[package]),
            retrotp[package] / (retrotp[package] + retrofn[package]),
            ddisasmtp[package] / (ddisasmtp[package] + ddisasmfp[package]),
            ddisasmtp[package] / (ddisasmtp[package] + ddisasmfn[package])))

    for arch in ARCHS:
        if arch == 'x86':
            print('| %s | %d | %d | %d | - | - | - | %d | %d | %d |' % (
                arch,
                ramblrtp[arch],
                ramblrfp[arch],
                ramblrfn[arch],
                ddisasmtp[arch],
                ddisasmfp[arch],
                ddisasmfn[arch]))
        else:
            print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
                arch,
                ramblrtp[arch],
                ramblrfp[arch],
                ramblrfn[arch],
                retrotp[arch],
                retrofp[arch],
                retrofn[arch],
                ddisasmtp[arch],
                ddisasmfp[arch],
                ddisasmfn[arch]))
    for arch in ARCHS:
        if arch == 'x86':
            print('| %s | %.3f | %.3f | - | - | %.3f | %.3f |' % (
                arch,
                ramblrtp[arch] / (ramblrtp[arch] + ramblrfp[arch]),
                ramblrtp[arch] / (ramblrtp[arch] + ramblrfn[arch]),
                ddisasmtp[arch] / (ddisasmtp[arch] + ddisasmfp[arch]),
                ddisasmtp[arch] / (ddisasmtp[arch] + ddisasmfn[arch])))
        else:
            print('| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |' % (
                arch,
                ramblrtp[arch] / (ramblrtp[arch] + ramblrfp[arch]),
                ramblrtp[arch] / (ramblrtp[arch] + ramblrfn[arch]),
                retrotp[arch] / (retrotp[arch] + retrofp[arch]),
                retrotp[arch] / (retrotp[arch] + retrofn[arch]),
                ddisasmtp[arch] / (ddisasmtp[arch] + ddisasmfp[arch]),
                ddisasmtp[arch] / (ddisasmtp[arch] + ddisasmfn[arch])))

    for compiler in COMPILERS:
        print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
            compiler,
            ramblrtp[compiler],
            ramblrfp[compiler],
            ramblrfn[compiler],
            retrotp[compiler],
            retrofp[compiler],
            retrofn[compiler],
            ddisasmtp[compiler],
            ddisasmfp[compiler],
            ddisasmfn[compiler]))
    for compiler in COMPILERS:
        print('| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |' % (
            compiler,
            ramblrtp[compiler] / (ramblrtp[compiler] + ramblrfp[compiler]),
            ramblrtp[compiler] / (ramblrtp[compiler] + ramblrfn[compiler]),
            retrotp[compiler] / (retrotp[compiler] + retrofp[compiler]),
            retrotp[compiler] / (retrotp[compiler] + retrofn[compiler]),
            ddisasmtp[compiler] / (ddisasmtp[compiler] + ddisasmfp[compiler]),
            ddisasmtp[compiler] / (ddisasmtp[compiler] + ddisasmfn[compiler])))

    for pie in PIES:
        if pie == 'pie':
            print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
                pie,
                ramblrtp[pie],
                ramblrfp[pie],
                ramblrfn[pie],
                retrotp[pie],
                retrofp[pie],
                retrofn[pie],
                ddisasmtp[pie],
                ddisasmfp[pie],
                ddisasmfn[pie]))
        else:
            print('| %s | %d | %d | %d | - | - | - | %d | %d | %d |' % (
                pie,
                ramblrtp[pie],
                ramblrfp[pie],
                ramblrfn[pie],
                ddisasmtp[pie],
                ddisasmfp[pie],
                ddisasmfn[pie]))
    for pie in PIES:
        if pie == 'pie':
            print('| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |' % (
                pie,
                0, #ramblrtp[pie] / (ramblrtp[pie] + ramblrfp[pie]),
                0, #ramblrtp[pie] / (ramblrtp[pie] + ramblrfn[pie]),
                retrotp[pie] / (retrotp[pie] + retrofp[pie]),
                retrotp[pie] / (retrotp[pie] + retrofn[pie]),
                ddisasmtp[pie] / (ddisasmtp[pie] + ddisasmfp[pie]),
                ddisasmtp[pie] / (ddisasmtp[pie] + ddisasmfn[pie])))
        else:
            print('| %s | %.3f | %.3f | - | - | %.3f | %.3f |' % (
                pie,
                ramblrtp[pie] / (ramblrtp[pie] + ramblrfp[pie]),
                ramblrtp[pie] / (ramblrtp[pie] + ramblrfn[pie]),
                ddisasmtp[pie] / (ddisasmtp[pie] + ddisasmfp[pie]),
                ddisasmtp[pie] / (ddisasmtp[pie] + ddisasmfn[pie])))

    for opti in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
        print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
            opti,
            ramblrtp[opti],
            ramblrfp[opti],
            ramblrfn[opti],
            retrotp[opti],
            retrofp[opti],
            retrofn[opti],
            ddisasmtp[opti],
            ddisasmfp[opti],
            ddisasmfn[opti]))
    for opti in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
        print('| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |' % (
            opti,
            ramblrtp[opti] / (ramblrtp[opti] + ramblrfp[opti]),
            ramblrtp[opti] / (ramblrtp[opti] + ramblrfn[opti]),
            retrotp[opti] / (retrotp[opti] + retrofp[opti]),
            retrotp[opti] / (retrotp[opti] + retrofn[opti]),
            ddisasmtp[opti] / (ddisasmtp[opti] + ddisasmfp[opti]),
            ddisasmtp[opti] / (ddisasmtp[opti] + ddisasmfn[opti])))

    for linker in ['bfd', 'gold']:
        print('| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d |' % (
            linker,
            ramblrtp[linker],
            ramblrfp[linker],
            ramblrfn[linker],
            retrotp[linker],
            retrofp[linker],
            retrofn[linker],
            ddisasmtp[linker],
            ddisasmfp[linker],
            ddisasmfn[linker]))
    for linker in ['bfd', 'gold']:
        print('| %s | %.3f | %.3f | %.3f | %.3f | %.3f | %.3f |' % (
            linker,
            ramblrtp[linker] / (ramblrtp[linker] + ramblrfp[linker]),
            ramblrtp[linker] / (ramblrtp[linker] + ramblrfn[linker]),
            retrotp[linker] / (retrotp[linker] + retrofp[linker]),
            retrotp[linker] / (retrotp[linker] + retrofn[linker]),
            ddisasmtp[linker] / (ddisasmtp[linker] + ddisasmfp[linker]),
            ddisasmtp[linker] / (ddisasmtp[linker] + ddisasmfn[linker])))


    print(numramblr, numretro, numddisasm)


if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    stat_dir = sys.argv[2]
    #stat_dir = '/home/soomink/stat'
    main(bench_dir, stat_dir)
