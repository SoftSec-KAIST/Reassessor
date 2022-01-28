import os, sys
from utils import *

ramblrfps = [{}, {}, {}, {}, {}, {}, {}, {}]
ramblrfns = [{}, {}, {}, {}, {}, {}, {}]
ramblrtps = [{}, {}, {}, {}, {}, {}, {}]
retrofps = [{}, {}, {}, {}, {}, {}, {}, {}]
retrofns = [{}, {}, {}, {}, {}, {}, {}]
retrotps = [{}, {}, {}, {}, {}, {}, {}]
ddisasmfps = [{}, {}, {}, {}, {}, {}, {}, {}]
ddisasmfns = [{}, {}, {}, {}, {}, {}, {}]
ddisasmtps = [{}, {}, {}, {}, {}, {}, {}]

ramblrtp = [0, 0, 0, 0, 0, 0, 0]
ramblrfp = [0, 0, 0, 0, 0, 0, 0, 0]
ramblrfn = [0, 0, 0, 0, 0, 0, 0]
retrotp = [0, 0, 0, 0, 0, 0, 0]
retrofp = [0, 0, 0, 0, 0, 0, 0, 0]
retrofn = [0, 0, 0, 0, 0, 0, 0]
ddisasmtp = [0, 0, 0, 0, 0, 0, 0]
ddisasmfp = [0, 0, 0, 0, 0, 0, 0, 0]
ddisasmfn = [0, 0, 0, 0, 0, 0, 0]

ramblrbin = 0
retrobin = 0
ddisasmbin = 0

ramblrgt = 0
retrogt = 0
ddisasmgt = 0

ramblr_e8_7 = 0
retro_e8_7 = 0
ddisasm_e8_7 = 0


x64pieramblrtp = 0
x64pieramblrfp = 0
x64pieramblrfn = 0
x64pieretrotp = 0
x64pieretrofp = 0
x64pieretrofn = 0
x64pieddisasmtp = 0
x64pieddisasmfp = 0
x64pieddisasmfn = 0
x86pieddisasmtp = 0
x86pieddisasmfp = 0
x86pieddisasmfn = 0

x64pieretroprog = 0
x64pieddisasmprog = 0

ramblr_ebins1 = {'x86pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x86nopie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64nopie':[0, 0, 0, 0, 0, 0, 0, 0]}
retro_ebins1 = {'x86pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x86nopie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64nopie':[0, 0, 0, 0, 0, 0, 0, 0]}
ddisasm_ebins1 = {'x86pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x86nopie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64nopie':[0, 0, 0, 0, 0, 0, 0, 0]}
ramblr_ebins2 = {'x86pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x86nopie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64nopie':[0, 0, 0, 0, 0, 0, 0, 0]}
retro_ebins2 = {'x86pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x86nopie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64nopie':[0, 0, 0, 0, 0, 0, 0, 0]}
ddisasm_ebins2 = {'x86pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x86nopie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64pie':[0, 0, 0, 0, 0, 0, 0, 0],
        'x64nopie':[0, 0, 0, 0, 0, 0, 0, 0]}

settings = set()

def report_ramblr(key):
    print('Ramblr, %s' % key)
    for i in range(7):
        tp = ramblrtps[i][key]
        fp = ramblrfps[i][key]
        fn = ramblrfns[i][key]
        if tp + fp == 0:
            prec = '-'
        else:
            prec = '%.2f\\%%' % (tp * 100 / (tp + fp))
        if tp + fn == 0:
            rec = '-'
        else:
            rec = '%.2f\\%%' % (tp * 100 / (tp + fn))
        #print('  & \\scriptsize %s & \\scriptsize %s' % (prec, rec))
        print(tp, fp, fn)

def report_retro(key):
    print('RetroWrite, %s' % key)
    for i in range(7):
        tp = retrotps[i][key]
        fp = retrofps[i][key]
        fn = retrofns[i][key]
        if tp + fp == 0:
            prec = '-'
        else:
            prec = '%.2f\\%%' % (tp * 100 / (tp + fp))
        if tp + fn == 0:
            rec = '-'
        else:
            rec = '%.2f\\%%' % (tp * 100 / (tp + fn))
        #print('  & \\scriptsize %s & \\scriptsize %s' % (prec, rec))
        print(tp, fp, fn)

def report_ddisasm(key):
    print('DDisasm, %s' % key)
    for i in range(7):
        tp = ddisasmtps[i][key]
        fp = ddisasmfps[i][key]
        fn = ddisasmfns[i][key]
        if tp + fp == 0:
            prec = '-'
        else:
            prec = '%.2f\\%%' % (tp * 100 / (tp + fp))
        if tp + fn == 0:
            rec = '-'
        else:
            rec = '%.2f\\%%' % (tp * 100 / (tp + fn))
        #print('  & \\scriptsize %s & \\scriptsize %s' % (prec, rec))
        print(tp, fp, fn)

def report_key(key):
    report_ramblr(key)
    report_retro(key)
    report_ddisasm(key)

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

    for i in range(8):
        if i == 7:
            print('FP', ramblrfp[i], retrofp[i], ddisasmfp[i])
        else:
            print('FP', ramblrfp[i], retrofp[i], ddisasmfp[i])
            print('FN', ramblrfn[i], retrofn[i], ddisasmfn[i])

    print('---')
    for i in range(7):
        print('TP', ramblrtp[i], retrotp[i], ddisasmtp[i])

    print('---')
    for i in range(7):
        print('ET', ramblrtp[i] + ramblrfn[i], retrotp[i] + retrofn[i], ddisasmtp[i] + ddisasmfn[i])

    print('---')
    print('Bins', ramblrbin, retrobin, ddisasmbin)
    print('Relocs', ramblrgt, retrogt, ddisasmgt)

    print('---')
    print('Retro', x64pieretrotp, x64pieretrofp, x64pieretrofn, x64pieretrotp * 100 / (x64pieretrotp + x64pieretrofn))
    print('DDisasm', x64pieddisasmtp, x64pieddisasmfp, x64pieddisasmfn, x64pieddisasmtp * 100 / (x64pieddisasmtp + x64pieddisasmfn))
    print('DDisasm', x86pieddisasmtp, x86pieddisasmfp, x86pieddisasmfn, x86pieddisasmtp * 100 / (x86pieddisasmtp + x86pieddisasmfn))

    print('e8_7', ramblr_e8_7, retro_e8_7, ddisasm_e8_7)

    print(settings)

    print(x64pieddisasmprog, x64pieretroprog)

    x = 0
    xx = 0
    y = 0
    yy = 0
    z = 0
    zz = 0
    for i in [1, 3, 5]:
        x += ramblrtp[i]
        xx += ramblrtp[i] + ramblrfn[i]
        y += retrotp[i]
        yy += retrotp[i] + retrofn[i]
        z += ddisasmtp[i]
        zz += ddisasmtp[i] + ddisasmfn[i]
    print('Composite %.3f, %.3f, %.3f' % (x /xx, y/yy, z/zz))

    #print('---')
    #print('x86pie')
    #for i in range(8):
    #    print('%d %d %d' % (ramblr_ebins['x86pie'][i], retro_ebins['x86pie'][i], ddisasm_ebins['x86pie'][i]))
    #print('x86nopie')
    #for i in range(8):
    #    print('%d %d %d' % (ramblr_ebins['x86nopie'][i], retro_ebins['x86nopie'][i], ddisasm_ebins['x86nopie'][i]))
    #print('x64pie')
    #for i in range(8):
    #    print('%d %d %d' % (ramblr_ebins['x64pie'][i], retro_ebins['x64pie'][i], ddisasm_ebins['x64pie'][i]))
    #print('x64nopie')
    #for i in range(8):
    #    print('%d %d %d' % (ramblr_ebins['x64nopie'][i], retro_ebins['x64nopie'][i], ddisasm_ebins['x64nopie'][i]))

    #print('---')
    #for i in range(8):
    #    print('%d %d' % (retro_ebins['x64pie'][i], ddisasm_ebins['x64pie'][i]))
    #for i in range(8):
    #    print('%d %d' % (retro_ebins['x64pie'][i], ddisasm_ebins['x64pie'][i]))
    #for i in range(8):
    #    print('%d %d' % (ramblr_ebins['x86nopie'][i] + ramblr_ebins['x64nopie'][i], ddisasm_ebins['x86nopie'][i] + ddisasm_ebins['x64nopie'][i]))

    print('---')
    for i in range(8):
        print('%d %d' % (retro_ebins2['x64pie'][i], ddisasm_ebins2['x64pie'][i]))
    for i in range(8):
        print('%d %d' % (ramblr_ebins1['x86nopie'][i] + ramblr_ebins1['x64nopie'][i], ddisasm_ebins1['x86nopie'][i] + ddisasm_ebins1['x64nopie'][i]))
    for i in range(8):
        print('%d %d' % (ramblr_ebins1['x64nopie'][i], ddisasm_ebins1['x64nopie'][i]))

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

    for i in range(7):
        if s not in ramblrtps[i]:
            ramblrtps[i][s] = 0
        if s not in retrotps[i]:
            retrotps[i][s] = 0
        if s not in ddisasmtps[i]:
            ddisasmtps[i][s] = 0

def handle_bin(package, arch, compiler, pie, opti, linker, stat_base, name):
    global ramblrbin, retrobin, ddisasmbin, ramblrgt, retrogt, ddisasmgt, x64pieretrotp, x64pieretrofp, x64pieretrofn, x64pieddisasmtp, x64pieddisasmfp, x64pieddisasmfn, x86pieddisasmtp, x86pieddisasmfp, x86pieddisasmfn, x64pieddisasmprog, x64pieretroprog, ddisasm_e8_7, retro_e8_7, ramblr_e8_7
    has_ramblr = False
    has_retro = False
    has_ddisasm = False
    err_ramblr = [False, False, False, False, False, False, False, False]
    err_retro = [False, False, False, False, False, False, False, False]
    err_ddisasm = [False, False, False, False, False, False, False, False]
    if pie != 'pie':
        ramblr_pr = os.path.join(stat_base, 'ramblr', name)
        if os.path.exists(ramblr_pr):
            has_ramblr = True
            ramblrbin += 1
            #print(ramblr_pr)
            with open(ramblr_pr) as f:
                lines = f.readlines()
            #lines = [lines[0], lines[2], lines[4], lines[6], lines[8], lines[10], lines[12], lines[14]]
            lines = list(map(lambda x: list(map(int, x.strip().split(','))), lines))
            for i in range(8):
                if i == 7:
                    ramblrfps[i][package] += lines[i][0]
                    ramblrfps[i][arch] += lines[i][0]
                    ramblrfps[i][compiler] += lines[i][0]
                    ramblrfps[i][pie] += lines[i][0]
                    ramblrfps[i][opti] += lines[i][0]
                    ramblrfps[i][linker] += lines[i][0]

                    ramblrfp[i] += lines[i][0]

                    if lines[i][0] > 0:
                        #ramblr_ebins[arch+pie][i] += 1
                        err_ramblr[i] = True
                else:
                    ramblrtps[i][package] += lines[i][0]
                    ramblrfps[i][package] += lines[i][1]
                    ramblrfns[i][package] += lines[i][2]
                    ramblrtps[i][arch] += lines[i][0]
                    ramblrfps[i][arch] += lines[i][1]
                    ramblrfns[i][arch] += lines[i][2]
                    ramblrtps[i][compiler] += lines[i][0]
                    ramblrfps[i][compiler] += lines[i][1]
                    ramblrfns[i][compiler] += lines[i][2]
                    ramblrtps[i][pie] += lines[i][0]
                    ramblrfps[i][pie] += lines[i][1]
                    ramblrfns[i][pie] += lines[i][2]
                    ramblrtps[i][opti] += lines[i][0]
                    ramblrfps[i][opti] += lines[i][1]
                    ramblrfns[i][opti] += lines[i][2]
                    ramblrtps[i][linker] += lines[i][0]
                    ramblrfps[i][linker] += lines[i][1]
                    ramblrfns[i][linker] += lines[i][2]

                    ramblrtp[i] += lines[i][0]
                    ramblrfp[i] += lines[i][1]
                    ramblrfn[i] += lines[i][2]

                    if lines[i][1] + lines[i][2] > 0:
                        #ramblr_ebins[arch+pie][i] += 1
                        err_ramblr[i] = True
            ramblrgt += lines[8][0]
            ramblr_e8_7 += lines[9][0]
    retro_pr = os.path.join(stat_base, 'retro_sym', name)
    if os.path.exists(retro_pr):
        has_retro = True
        retrobin += 1
        #print(retro_pr)
        with open(retro_pr) as f:
            lines = f.readlines()
        #lines = [lines[0], lines[2], lines[4], lines[6], lines[8], lines[10], lines[12], lines[14]]
        lines = list(map(lambda x: list(map(int, x.strip().split(','))), lines))
        for i in range(8):
            if i == 7:
                retrofps[i][package] += lines[i][0]
                retrofps[i][arch] += lines[i][0]
                retrofps[i][compiler] += lines[i][0]
                retrofps[i][pie] += lines[i][0]
                retrofps[i][opti] += lines[i][0]
                retrofps[i][linker] += lines[i][0]

                retrofp[i] += lines[i][0]

                if lines[i][0] > 0:
                    #retro_ebins[arch+pie][i] += 1
                    err_retro[i] = True
            else:
                retrotps[i][package] += lines[i][0]
                retrofps[i][package] += lines[i][1]
                retrofns[i][package] += lines[i][2]
                retrotps[i][arch] += lines[i][0]
                retrofps[i][arch] += lines[i][1]
                retrofns[i][arch] += lines[i][2]
                retrotps[i][compiler] += lines[i][0]
                retrofps[i][compiler] += lines[i][1]
                retrofns[i][compiler] += lines[i][2]
                retrotps[i][pie] += lines[i][0]
                retrofps[i][pie] += lines[i][1]
                retrofns[i][pie] += lines[i][2]
                retrotps[i][opti] += lines[i][0]
                retrofps[i][opti] += lines[i][1]
                retrofns[i][opti] += lines[i][2]
                retrotps[i][linker] += lines[i][0]
                retrofps[i][linker] += lines[i][1]
                retrofns[i][linker] += lines[i][2]

                retrotp[i] += lines[i][0]
                retrofp[i] += lines[i][1]
                retrofn[i] += lines[i][2]

                if lines[i][1] + lines[i][2] > 0:
                    #retro_ebins[arch+pie][i] += 1
                    err_retro[i] = True
        retrogt += lines[8][0]
        retro_e8_7 += lines[9][0]
        if arch == 'x64' and pie == 'pie':
            x64pieretrotp += lines[6][0]
            x64pieretrofp += lines[6][1]
            x64pieretrofn += lines[6][2]
        if lines[6][2] != 0:
            x64pieretroprog += 1
    ddisasm_pr = os.path.join(stat_base, 'ddisasm', name)
    if os.path.exists(ddisasm_pr):
        has_ddisasm = True
        ddisasmbin += 1
        #print(ddisasm_pr)
        with open(ddisasm_pr) as f:
            lines = f.readlines()
        #lines = [lines[0], lines[2], lines[4], lines[6], lines[8], lines[10], lines[12], lines[14]]
        lines = list(map(lambda x: list(map(int, x.strip().split(','))), lines))
        for i in range(8):
            if i == 7:
                ddisasmfps[i][package] += lines[i][0]
                ddisasmfps[i][arch] += lines[i][0]
                ddisasmfps[i][compiler] += lines[i][0]
                ddisasmfps[i][pie] += lines[i][0]
                ddisasmfps[i][opti] += lines[i][0]
                ddisasmfps[i][linker] += lines[i][0]

                ddisasmfp[i] += lines[i][0]

                if lines[i][0] > 0:
                    #ddisasm_ebins[arch+pie][i] += 1
                    err_ddisasm[i] = True
            else:
                ddisasmtps[i][package] += lines[i][0]
                ddisasmfps[i][package] += lines[i][1]
                ddisasmfns[i][package] += lines[i][2]
                ddisasmtps[i][arch] += lines[i][0]
                ddisasmfps[i][arch] += lines[i][1]
                ddisasmfns[i][arch] += lines[i][2]
                ddisasmtps[i][compiler] += lines[i][0]
                ddisasmfps[i][compiler] += lines[i][1]
                ddisasmfns[i][compiler] += lines[i][2]
                ddisasmtps[i][pie] += lines[i][0]
                ddisasmfps[i][pie] += lines[i][1]
                ddisasmfns[i][pie] += lines[i][2]
                ddisasmtps[i][opti] += lines[i][0]
                ddisasmfps[i][opti] += lines[i][1]
                ddisasmfns[i][opti] += lines[i][2]
                ddisasmtps[i][linker] += lines[i][0]
                ddisasmfps[i][linker] += lines[i][1]
                ddisasmfns[i][linker] += lines[i][2]

                ddisasmtp[i] += lines[i][0]
                ddisasmfp[i] += lines[i][1]
                ddisasmfn[i] += lines[i][2]

                if lines[i][1] + lines[i][2] > 0:
                    #ddisasm_ebins[arch+pie][i] += 1
                    err_ddisasm[i] = True
        ddisasmgt += lines[8][0]
        ddisasm_e8_7 += lines[9][0]
        if arch == 'x64' and pie == 'pie':
            x64pieddisasmtp += lines[6][0]
            x64pieddisasmfp += lines[6][1]
            x64pieddisasmfn += lines[6][2]
        if arch == 'x86' and pie == 'pie':
            x86pieddisasmtp += lines[6][0]
            x86pieddisasmfp += lines[6][1]
            x86pieddisasmfn += lines[6][2]
        if lines[6][2] != 0:
            settings.add(arch+pie)
            x64pieddisasmprog += 1

    if has_ramblr and has_ddisasm:
        for i in range(8):
            if err_ramblr[i]:
                ramblr_ebins1[arch+pie][i] += 1
            if err_ddisasm[i]:
                ddisasm_ebins1[arch+pie][i] += 1
    if has_retro and has_ddisasm:
        for i in range(8):
            if err_retro[i]:
                retro_ebins2[arch+pie][i] += 1
            if err_ddisasm[i]:
                ddisasm_ebins2[arch+pie][i] += 1


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
    #stat_dir = '/home/soomink/pr2'
    main(bench_dir, stat_dir)
