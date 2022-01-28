import sys, os
from utils import *
import roman

def main(bench_dir, stat_dir):
    gtins = {}
    gtdata = {}
    ddisasmins = {}
    ddisasminstarget = {}
    ddisasmdata = {}
    ramblrins = {}
    ramblrinstarget = {}
    ramblrdata = {}
    retroins = {}
    retroinstarget = {}
    retrodata = {}
    gt = [0, 0, 0, 0, 0, 0, 0]
    gttot = 0
    ddisasmtot = 0
    ramblrtot = 0
    retrotot = 0

    optbins = {}
    opttotbins = {}
    totbins = 0

    for package, arch, compiler, pie, opt in gen_options():
        if package not in gtins:
            gtins[package] = [0, 0, 0, 0, 0, 0, 0]
        if package not in gtdata:
            gtdata[package] = [0, 0, 0, 0, 0, 0, 0]
        if arch not in gtins:
            gtins[arch] = [0, 0, 0, 0, 0, 0, 0]
        if arch not in gtdata:
            gtdata[arch] = [0, 0, 0, 0, 0, 0, 0]
        if compiler not in gtins:
            gtins[compiler] = [0, 0, 0, 0, 0, 0, 0]
        if compiler not in gtdata:
            gtdata[compiler] = [0, 0, 0, 0, 0, 0, 0]
        if pie not in gtins:
            gtins[pie] = [0, 0, 0, 0, 0, 0, 0]
        if pie not in gtdata:
            gtdata[pie] = [0, 0, 0, 0, 0, 0, 0]
        opti, linker = opt.split('-')
        if opti not in gtins:
            gtins[opti] = [0, 0, 0, 0, 0, 0, 0]
        if opti not in gtdata:
            gtdata[opti] = [0, 0, 0, 0, 0, 0, 0]
        if linker not in gtins:
            gtins[linker] = [0, 0, 0, 0, 0, 0, 0]
        if linker not in gtdata:
            gtdata[linker] = [0, 0, 0, 0, 0, 0, 0]

        if opti not in optbins:
            optbins[opti] = 0
        if opti not in opttotbins:
            opttotbins[opti] = 0

        '''
        if package+compiler not in gtins:
            gtins[package+compiler] = 0
        if package+compiler not in gtdata:
            gtdata[package+compiler] = 0
        if "total"+package+compiler not in gtins:
            gtins["total"+package+compiler] = 0
        if "total"+package+compiler not in gtdata:
            gtdata["total"+package+compiler] = 0
        '''


        #print(package, arch, compiler, pie, opt)
        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        for name in os.listdir(bin_dir):
            stat_file = os.path.join(stat_base, name, 'type_count')
            if not os.path.exists(stat_file):
                continue
            totbins += 1
            opttotbins[opti] += 1
            with open(stat_file) as f:
                lines = f.readlines()
            lines = list(map(lambda x: x.strip(), lines))
            gti = list(map(int, lines[0].split(',')))
            for i in range(7):
                gtins[package][i] += gti[i]
                gtins[arch][i] += gti[i]
                gtins[compiler][i] += gti[i]
                gtins[pie][i] += gti[i]
                gtins[opti][i] += gti[i]
                gtins[linker][i] += gti[i]
                gttot += gti[i]
            gtd = list(map(int, lines[1].split(',')))
            for i in range(7):
                gtdata[package][i] += gtd[i]
                gtdata[arch][i] += gtd[i]
                gtdata[compiler][i] += gtd[i]
                gtdata[pie][i] += gtd[i]
                gtdata[opti][i] += gtd[i]
                gtdata[linker][i] += gtd[i]
                gttot += gtd[i]
            nc = 0
            for i in [1, 3, 5, 6]:
                nc += gti[i] + gtd[i]
            if nc > 0:
                optbins[opti] += 1
            '''
            if arch == 'x86' and pie == 'nopie':
                for i in range(7):
                    gtins["total"+package+compiler] += gti[i]
                    gtdata["total"+package+compiler] += gtd[i]
                    gt[i] += gti[i] + gtd[i]
                gtins[package+compiler] += gti[6]
                gtdata[package+compiler] += gtd[6]
            '''
            '''
            ddisasmi = list(map(int, lines[2].split(',')))
            for i in range(7):
                ddisasmins[arch+pie][i] += ddisasmi[i]
            '''
            ddisasmit = list(map(int, lines[3].split(',')))
            for i in range(7):
                #ddisasminstarget[arch+pie][i] += ddisasmit[i]
                ddisasmtot += ddisasmit[i]
            ddisasmd = list(map(int, lines[4].split(',')))
            for i in range(7):
                #ddisasmdata[arch+pie][i] += ddisasmd[i]
                ddisasmtot += ddisasmd[i]
            '''
            ramblri = list(map(int, lines[5].split(',')))
            for i in range(7):
                ramblrins[arch+pie][i] += ramblri[i]
            '''
            ramblrit = list(map(int, lines[6].split(',')))
            for i in range(7):
                #ramblrinstarget[arch+pie][i] += ramblrit[i]
                ramblrtot += ramblrit[i]
            ramblrd = list(map(int, lines[7].split(',')))
            for i in range(7):
                #ramblrdata[arch+pie][i] += ramblrd[i]
                ramblrtot += ramblrd[i]
            '''
            retroi = list(map(int, lines[8].split(',')))
            for i in range(7):
                retroins[arch+pie][i] += retroi[i]
            '''
            retroit = list(map(int, lines[9].split(',')))
            for i in range(7):
                #retroinstarget[arch+pie][i] += retroit[i]
                retrotot += retroit[i]
            retrod = list(map(int, lines[10].split(',')))
            for i in range(7):
                #retrodata[arch+pie][i] += retrod[i]
                retrotot += retrod[i]

    for package in PACKAGES:
        lbl = 0
        atomic = 0
        composite = 0
        for i in range(7):
            lbl += gtins[package][i]
            lbl += gtdata[package][i]
            if i in [0, 2, 4]:
                atomic += gtins[package][i]
                atomic += gtdata[package][i]
            else:
                composite += gtins[package][i]
                composite += gtdata[package][i]
        print('%s & %d & %.3f & %.3f \\\\' % (
            package,
            lbl,
            atomic / lbl * 100,
            composite / lbl * 100
            ))

    for arch in ARCHS:
        lbl = 0
        atomic = 0
        composite = 0
        for i in range(7):
            lbl += gtins[arch][i]
            lbl += gtdata[arch][i]
            if i in [0, 2, 4]:
                atomic += gtins[arch][i]
                atomic += gtdata[arch][i]
            else:
                composite += gtins[arch][i]
                composite += gtdata[arch][i]
        print('%s & %d & %.3f & %.3f \\\\' % (
            arch,
            lbl,
            atomic / lbl * 100,
            composite / lbl * 100
            ))

    for compiler in COMPILERS:
        lbl = 0
        atomic = 0
        composite = 0
        for i in range(7):
            lbl += gtins[compiler][i]
            lbl += gtdata[compiler][i]
            if i in [0, 2, 4]:
                atomic += gtins[compiler][i]
                atomic += gtdata[compiler][i]
            else:
                composite += gtins[compiler][i]
                composite += gtdata[compiler][i]
        print('%s & %d & %.3f & %.3f \\\\' % (
            compiler,
            lbl,
            atomic / lbl * 100,
            composite / lbl * 100
            ))

    for pie in PIES:
        lbl = 0
        atomic = 0
        composite = 0
        for i in range(7):
            lbl += gtins[pie][i]
            lbl += gtdata[pie][i]
            if i in [0, 2, 4]:
                atomic += gtins[pie][i]
                atomic += gtdata[pie][i]
            else:
                composite += gtins[pie][i]
                composite += gtdata[pie][i]
        print('%s & %d & %.3f & %.3f \\\\' % (
            pie,
            lbl,
            atomic / lbl * 100,
            composite / lbl * 100
            ))

    for opti in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
        lbl = 0
        atomic = 0
        composite = 0
        for i in range(7):
            lbl += gtins[opti][i]
            lbl += gtdata[opti][i]
            if i in [0, 2, 4]:
                atomic += gtins[opti][i]
                atomic += gtdata[opti][i]
            else:
                composite += gtins[opti][i]
                composite += gtdata[opti][i]
        print('%s & %d & %.3f & %.3f \\\\' % (
            opti,
            lbl,
            atomic / lbl * 100,
            composite / lbl * 100
            ))

    for linker in ['bfd', 'gold']:
        lbl = 0
        atomic = 0
        composite = 0
        for i in range(7):
            lbl += gtins[linker][i]
            lbl += gtdata[linker][i]
            if i in [0, 2, 4]:
                atomic += gtins[linker][i]
                atomic += gtdata[linker][i]
            else:
                composite += gtins[linker][i]
                composite += gtdata[linker][i]
        print('%s & %d & %.3f & %.3f \\\\' % (
            linker,
            lbl,
            atomic / lbl * 100,
            composite / lbl * 100
            ))

    print(gttot, ramblrtot, retrotot, ddisasmtot)

    print('---')
    nn = 0
    for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
        print('%s - %.3f' % (opt, optbins[opt]*100/opttotbins[opt]))
        nn += optbins[opt]
    print(nn * 100 / totbins)

    '''
    x = 0
    y = 0
    z = 0
    for package in PACKAGES:
        for compiler in COMPILERS:
            print('%s : %d %d %.3f' % (
                package + " - " + compiler,
                gtins["total"+package+compiler] + gtdata["total"+package+compiler],
                gtins[package + compiler] + gtdata[package + compiler],
                (gtins[package + compiler] + gtdata[package + compiler]) / (gtins["total"+package+compiler] + gtdata["total"+package+compiler]) * 100
                ))
            x += gtins[package + compiler] + gtdata[package + compiler]
            y += gtins[package + compiler]
            z += gtdata[package + compiler]
    print('XXX %.3f %.3f' % (y / x * 100, z / x * 100))

    for i in range(7):
        print(gt[i])

    totlbl = 0
    totatomic = 0
    totcomposite = 0
    for arch in ['x86', 'x64']:
        for pie in ['pie', 'nopie']:
            print(arch + ' - ' + pie)
            lbl = 0
            atomic = 0
            composite = 0
            for i in range(7):
                print('| Type %s | %d / %d | %d (%d) / %d | %d (%d) / %d | %d (%d) / %d |' % (
                    roman.toRoman(i + 1).upper(),
                    gtins[arch+pie][i],
                    gtdata[arch+pie][i],
                    ddisasmins[arch+pie][i],
                    ddisasminstarget[arch+pie][i],
                    ddisasmdata[arch+pie][i],
                    ramblrins[arch+pie][i],
                    ramblrinstarget[arch+pie][i],
                    ramblrdata[arch+pie][i],
                    retroins[arch+pie][i],
                    retroinstarget[arch+pie][i],
                    retrodata[arch+pie][i]))
                print('%d,%d,%d,%d,%d,%d,%d,%d' % (
                    gtins[arch+pie][i],
                    gtdata[arch+pie][i],
                    ddisasminstarget[arch+pie][i],
                    ddisasmdata[arch+pie][i],
                    ramblrinstarget[arch+pie][i],
                    ramblrdata[arch+pie][i],
                    retroinstarget[arch+pie][i],
                    retrodata[arch+pie][i]))
                lbl += gtins[arch+pie][i] + gtdata[arch+pie][i]
                if i % 2 == 0:
                    atomic += gtins[arch+pie][i] + gtdata[arch+pie][i]
                if i % 2 == 1:
                    composite += gtins[arch+pie][i] + gtdata[arch+pie][i]
            print(lbl, atomic/lbl, composite/lbl)
            totlbl += lbl
            totatomic += atomic
            totcomposite += composite
    print(totlbl, totatomic/totlbl, totcomposite/totlbl)
    '''

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    stat_dir = sys.argv[2]
    #stat_dir = '/home/soomink/stat'
    main(bench_dir, stat_dir)
