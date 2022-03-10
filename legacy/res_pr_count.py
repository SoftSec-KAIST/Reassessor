import os, sys
from utils import *

ramblrfps = [{}, {}, {}, {}, {}, {}, {}, {}]
ramblrfns = [{}, {}, {}, {}, {}, {}, {}]
ramblrps = [{}, {}, {}, {}, {}, {}, {}, {}]
retrofps = [{}, {}, {}, {}, {}, {}, {}, {}]
retrofns = [{}, {}, {}, {}, {}, {}, {}]
retrops = [{}, {}, {}, {}, {}, {}, {}, {}]
ddisasmfps = [{}, {}, {}, {}, {}, {}, {}, {}]
ddisasmfns = [{}, {}, {}, {}, {}, {}, {}]
ddisasmps = [{}, {}, {}, {}, {}, {}, {}, {}]

def report_key(key):
    print(key)
    for i in range(8):
        ramblrp = ramblrps[i][key]
        ramblrfp = ramblrfps[i][key]
        ramblrtp = ramblrp - ramblrfp
        if ramblrtp < 0:
            ramblrtp = 0
        assert ramblrtp >= 0
        if ramblrp == 0:
            ramblrprec = '-'
        else:
            ramblrprec = '%.1f' % (ramblrtp / ramblrp * 100)
        retrop = retrops[i][key]
        retrofp = retrofps[i][key]
        retrotp = retrop - retrofp
        if retrotp < 0:
            retrotp = 0
        assert retrotp >= 0
        if retrop == 0:
            retroprec = '-'
        else:
            retroprec = '%.1f' % (retrotp / retrop * 100)
        ddisasmp = ddisasmps[i][key]
        ddisasmfp = ddisasmfps[i][key]
        ddisasmtp = ddisasmp - ddisasmfp
        if ddisasmtp < 0:
            ddisasmtp = 0
        assert ddisasmtp >= 0
        if ddisasmp == 0:
            ddisasmprec = '-'
        else:
            ddisasmprec = '%.1f' % (ddisasmtp / ddisasmp * 100)

        print('Type %d Prec | %s | %s | %s' % (i + 1, ramblrprec, retroprec, ddisasmprec))
    for i in range(7):
        ramblrp = ramblrps[i][key]
        ramblrfp = ramblrfps[i][key]
        ramblrtp = ramblrp - ramblrfp
        ramblrfn = ramblrfns[i][key]
        if ramblrtp < 0:
            ramblrtp = 0
        assert ramblrtp >= 0
        if ramblrtp + ramblrfn == 0:
            ramblrrec = '-'
        else:
            ramblrrec = '%.1f' % (ramblrtp / (ramblrtp + ramblrfn) * 100)
        retrop = retrops[i][key]
        retrofp = retrofps[i][key]
        retrotp = retrop - retrofp
        retrofn = retrofns[i][key]
        if retrotp < 0:
            retrotp = 0
        assert retrotp >= 0
        if retrotp + retrofn == 0:
            retrorec = '-'
        else:
            retrorec = '%.1f' % (retrotp / (retrotp + retrofn) * 100)
        ddisasmp = ddisasmps[i][key]
        ddisasmfp = ddisasmfps[i][key]
        ddisasmtp = ddisasmp - ddisasmfp
        ddisasmfn = ddisasmfns[i][key]
        if ddisasmtp < 0:
            ddisasmtp = 0
        assert ddisasmtp >= 0
        if ddisasmtp + ddisasmfn == 0:
            ddisasmrec = '-'
        else:
            ddisasmrec = '%.1f' % (ddisasmtp / (ddisasmtp + ddisasmfn) * 100)
        print('Type %d Rec | %s | %s | %s' % (i + 1, ramblrrec, retrorec, ddisasmrec))

def report():
    for package in PACKAGES:
        report_key(package)
    for arch in ARCHS:
        report_key(arch)
    for compiler in COMPILERS:
        report_key(compiler)
    for pie in PIES:
        report_key(pie)
    for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
        report_key(opt)
    for linker in ['bfd', 'gold']:
        report_key(linker)

def init(s):
    for i in range(8):
        if s not in ramblrfps[i]:
            ramblrfps[i][s] = 0
        if s not in retrofps[i]:
            retrofps[i][s] = 0
        if s not in ddisasmfps[i]:
            ddisasmfps[i][s] = 0

    for i in range(7):
        if s not in ramblrfns[i]:
            ramblrfns[i][s] = 0
        if s not in retrofns[i]:
            retrofns[i][s] = 0
        if s not in ddisasmfns[i]:
            ddisasmfns[i][s] = 0

    for i in range(8):
        if s not in ramblrps[i]:
            ramblrps[i][s] = 0
        if s not in retrops[i]:
            retrops[i][s] = 0
        if s not in ddisasmps[i]:
            ddisasmps[i][s] = 0

def handle_type(package, arch, compiler, pie, opti, linker, stat_base, name):
    type_file = os.path.join(stat_base, name, 'type_count')
    if not os.path.exists(type_file):
        return
    with open(type_file) as f:
        lines = f.readlines()
    lines = list(map(lambda x: x.strip(), lines))
    ddisasmi = list(map(int, lines[2].split(',')))
    ddisasmd = list(map(int, lines[4].split(',')))
    ramblri = list(map(int, lines[5].split(',')))
    ramblrd = list(map(int, lines[7].split(',')))
    retroi = list(map(int, lines[8].split(',')))
    retrod = list(map(int, lines[10].split(',')))

    for i in range(7):
        ramblrps[i][package] += ramblri[i] + ramblrd[i]
        retrops[i][package] += retroi[i] + retrod[i]
        ddisasmps[i][package] += ddisasmi[i] + ddisasmd[i]
        ramblrps[i][arch] += ramblri[i] + ramblrd[i]
        retrops[i][arch] += retroi[i] + retrod[i]
        ddisasmps[i][arch] += ddisasmi[i] + ddisasmd[i]
        ramblrps[i][compiler] += ramblri[i] + ramblrd[i]
        retrops[i][compiler] += retroi[i] + retrod[i]
        ddisasmps[i][compiler] += ddisasmi[i] + ddisasmd[i]
        ramblrps[i][pie] += ramblri[i] + ramblrd[i]
        retrops[i][pie] += retroi[i] + retrod[i]
        ddisasmps[i][pie] += ddisasmi[i] + ddisasmd[i]
        ramblrps[i][opti] += ramblri[i] + ramblrd[i]
        retrops[i][opti] += retroi[i] + retrod[i]
        ddisasmps[i][opti] += ddisasmi[i] + ddisasmd[i]
        ramblrps[i][linker] += ramblri[i] + ramblrd[i]
        retrops[i][linker] += retroi[i] + retrod[i]
        ddisasmps[i][linker] += ddisasmi[i] + ddisasmd[i]

def handle_error(package, arch, compiler, pie, opti, linker, stat_base, name):
    err_file = os.path.join(stat_base, name, 'error_count')
    if not os.path.exists(err_file):
        return
    with open(err_file) as f:
        lines = f.readlines()
    lines = list(map(lambda x: x.strip(), lines))
    ddisasmi = list(map(int, lines[0].split(',')))
    ddisasmd = list(map(int, lines[1].split(',')))
    ramblri = list(map(int, lines[2].split(',')))
    ramblrd = list(map(int, lines[3].split(',')))
    retroi = list(map(int, lines[4].split(',')))
    retrod = list(map(int, lines[5].split(',')))

    for i in range(15):
        if i % 2 == 0:
            ramblrfps[i//2][package] += ramblri[i] + ramblrd[i]
            retrofps[i//2][package] += retroi[i] + retrod[i]
            ddisasmfps[i//2][package] += ddisasmi[i] + ddisasmd[i]
            ramblrfps[i//2][arch] += ramblri[i] + ramblrd[i]
            retrofps[i//2][arch] += retroi[i] + retrod[i]
            ddisasmfps[i//2][arch] += ddisasmi[i] + ddisasmd[i]
            ramblrfps[i//2][compiler] += ramblri[i] + ramblrd[i]
            retrofps[i//2][compiler] += retroi[i] + retrod[i]
            ddisasmfps[i//2][compiler] += ddisasmi[i] + ddisasmd[i]
            ramblrfps[i//2][pie] += ramblri[i] + ramblrd[i]
            retrofps[i//2][pie] += retroi[i] + retrod[i]
            ddisasmfps[i//2][pie] += ddisasmi[i] + ddisasmd[i]
            ramblrfps[i//2][opti] += ramblri[i] + ramblrd[i]
            retrofps[i//2][opti] += retroi[i] + retrod[i]
            ddisasmfps[i//2][opti] += ddisasmi[i] + ddisasmd[i]
            ramblrfps[i//2][linker] += ramblri[i] + ramblrd[i]
            retrofps[i//2][linker] += retroi[i] + retrod[i]
            ddisasmfps[i//2][linker] += ddisasmi[i] + ddisasmd[i]
        else:
            ramblrfns[i//2][package] += ramblri[i] + ramblrd[i]
            retrofns[i//2][package] += retroi[i] + retrod[i]
            ddisasmfns[i//2][package] += ddisasmi[i] + ddisasmd[i]
            ramblrfns[i//2][arch] += ramblri[i] + ramblrd[i]
            retrofns[i//2][arch] += retroi[i] + retrod[i]
            ddisasmfns[i//2][arch] += ddisasmi[i] + ddisasmd[i]
            ramblrfns[i//2][compiler] += ramblri[i] + ramblrd[i]
            retrofns[i//2][compiler] += retroi[i] + retrod[i]
            ddisasmfns[i//2][compiler] += ddisasmi[i] + ddisasmd[i]
            ramblrfns[i//2][pie] += ramblri[i] + ramblrd[i]
            retrofns[i//2][pie] += retroi[i] + retrod[i]
            ddisasmfns[i//2][pie] += ddisasmi[i] + ddisasmd[i]
            ramblrfns[i//2][opti] += ramblri[i] + ramblrd[i]
            retrofns[i//2][opti] += retroi[i] + retrod[i]
            ddisasmfns[i//2][opti] += ddisasmi[i] + ddisasmd[i]
            ramblrfns[i//2][linker] += ramblri[i] + ramblrd[i]
            retrofns[i//2][linker] += retroi[i] + retrod[i]
            ddisasmfns[i//2][linker] += ddisasmi[i] + ddisasmd[i]

def handle_bin(package, arch, compiler, pie, opti, linker, stat_base, name):
    handle_type(package, arch, compiler, pie, opti, linker, stat_base, name)
    handle_error(package, arch, compiler, pie, opti, linker, stat_base, name)

def main(bench_dir, stat_dir):

    for package, arch, compiler, pie, opt in gen_options():
        for i in range(8):
            init(package)
            init(arch)
            init(compiler)
            init(pie)
            opti, linker = opt.split('-')
            init(opti)
            init(linker)

        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        for name in os.listdir(bin_dir):
            handle_bin(package, arch, compiler, pie, opti, linker, stat_base, name)

    report()

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    stat_dir = sys.argv[2]
    #stat_dir = '/home/soomink/stat'
    main(bench_dir, stat_dir)
