import os, pickle, glob
from elftools.elf.elffile import ELFFile
from collections import namedtuple
from reassessor.lib.types import InstType, DataType
import numpy as np

BuildConf = namedtuple('BuildConf', ['target', 'pickle_file', 'arch', 'pie', 'opt'])

def gen_option(input_root, output_root):
    ret = []
    for package in ['spec_cpu2006', 'binutils-2.31.1', 'coreutils-8.30']:
        for arch in ['x64', 'x86']:
            for comp in ['clang', 'gcc']:
                for popt in ['pie', 'nopie']:
                    for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                        for lopt in ['bfd', 'gold']:
                            sub_dir = '%s/%s/%s/%s/%s-%s'%(package, arch, comp, popt, opt, lopt)
                            input_dir = '%s/%s'%(input_root, sub_dir)

                            for target in glob.glob('%s/reloc/*'%(input_dir)):

                                filename = os.path.basename(target)

                                pickle_file = '%s/%s/%s/norm_db/gt.db'%(output_root, sub_dir, filename)

                                ret.append(BuildConf(target, pickle_file, arch, popt, opt))
    return ret

class Stat:
    def __init__(self, conf):
        self.target = conf.target
        self.arch = conf.arch
        self.pie = conf.pie
        self.opt = conf.opt
        self.pickle_file = conf.pickle_file

        self.sym_list = [0,0,0,0,0,0,0,0,0]

    def examine(self):
        sym_list = [0,0,0,0,0,0,0,0,0]
        with open(self.pickle_file, 'rb') as f:
            gt = pickle.load(f)

            for _, inst in gt.Instrs.items():
                if not isinstance(inst, InstType):
                    continue
                if inst.disp:
                    sym_list[inst.disp.get_type()] += 1
                if inst.imm:
                    sym_list[inst.imm.get_type()] += 1

            for _, data in gt.Data.items():
                if not isinstance(data, DataType):
                    continue
                if data.value:
                    sym_list[data.value.get_type()] += 1

            total = 0
            for nType in range(1, 8):
                total += sym_list[nType]

        sym_list[0] = total
        self.sym_list = sym_list

def report(desc, sym_list):
    print('%-70s : %7d %7d %7d %7d %7d %7d %7d %10d'%(desc,
        sym_list[1], sym_list[2], sym_list[3], sym_list[4],
        sym_list[5], sym_list[6], sym_list[7], sym_list[0]))

class Manager:

    def __init__(self, input_root='./dataset', output_root='./output'):
        self.conf_list = gen_option(input_root, output_root)
        self.stat_list = []

    def run(self):
        print('%-70s : %7s %7s %7s %7s %7s %7s %7s %10s'%('',
                    'Type1', 'Type2','Type3', 'Type4',
                    'Type5', 'Type6','Type7', 'Total'))

        for conf in self.conf_list:
            stat = Stat(conf)
            stat.examine()
            report(stat.target, stat.sym_list)
            self.stat_list.append(stat)

    def summary(self):
        print()
        print('%-70s : %7s %7s %7s %7s %7s %7s %7s %10s'%('',
                    'Type1', 'Type2','Type3', 'Type4',
                    'Type5', 'Type6','Type7', 'Total'))

        summary = dict()
        summary['x64'] = dict()
        summary['x86'] = dict()
        summary['x64']['pie'] = [0,0,0,0,0,0,0,0,0]
        summary['x64']['nopie'] = [0,0,0,0,0,0,0,0,0]
        summary['x86']['pie'] = [0,0,0,0,0,0,0,0,0]
        summary['x86']['nopie'] = [0,0,0,0,0,0,0,0,0]
        summary['o0'] = [0,0,0,0,0,0,0,0,0]
        summary['o1'] = [0,0,0,0,0,0,0,0,0]
        summary['o2'] = [0,0,0,0,0,0,0,0,0]
        summary['o3'] = [0,0,0,0,0,0,0,0,0]
        summary['os'] = [0,0,0,0,0,0,0,0,0]
        summary['ofast'] = [0,0,0,0,0,0,0,0,0]
        summary['total'] = [0,0,0,0,0,0,0,0,0]

        num_of_bin_has_comp = 0
        for stat in self.stat_list:
            summary[stat.opt] = np.add(summary[stat.opt], stat.sym_list)
            summary[stat.arch][stat.pie] = np.add(summary[stat.arch][stat.pie], stat.sym_list)

            if summary[opt][2] + summary[opt][4] + summary[opt][6] + summary[opt][7] > 0:
                num_of_bin_has_comp += 1


        for arch in ['x86', 'x64']:
            for pie in ['nopie', 'pie']:
                desc = '%s-%s'%(arch, pie)
                report(desc, summary[arch][pie])

        for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
            summary['total'] = np.add(summary['total'], summary[opt])
            report(opt, summary[opt])

        report(opt, summary['total'])



        print('-------- Atomic vs. Composite --------')
        for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
            atomic = summary[opt][1] + summary[opt][3] + summary[opt][5]
            composite = summary[opt][2] + summary[opt][4] + summary[opt][6] + summary[opt][7]
            print('%30s: Atomic: %10d / Composite: %10d'%(opt, atomic, composite))


        atomic = summary['total'][1] + summary['total'][3] + summary['total'][5]
        composite = summary['total'][2] + summary['total'][4] + summary['total'][6] + summary['total'][7]

        print('%30s: Atomic: %10d / Composite: %10d'%('Total', atomic, composite))

        print('%5d/%5d binaries have composite relocs!'%(num_of_bin_has_comp / len(self.stat_list))

if __name__ == '__main__':

    mgr = Manager()
    mgr.run()
    mgr.summary()
