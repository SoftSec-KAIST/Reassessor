import os, pickle, glob
from elftools.elf.elffile import ELFFile
from collections import namedtuple
from reassessor.lib.types import InstType, DataType
import numpy as np
import multiprocessing

BuildConf = namedtuple('BuildConf', ['target', 'pickle_file', 'arch', 'pie', 'opt', 'key'])

global_key_list = []

def gen_option(input_root, output_root):
    ret = []
    global global_key_list
    for package in ['spec_cpu2006', 'binutils-2.31.1', 'coreutils-8.30']:
        for arch in ['x64', 'x86']:
            for comp in ['clang', 'gcc']:
                for popt in ['pie', 'nopie']:
                    for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                        for lopt in ['bfd', 'gold']:
                            sub_dir = '%s/%s/%s/%s/%s-%s'%(package, arch, comp, popt, opt, lopt)
                            input_dir = '%s/%s'%(input_root, sub_dir)

                            for target in glob.glob('%s/bin/*'%(input_dir)):

                                filename = os.path.basename(target)

                                pickle_file = '%s/%s/%s/norm_db/gt.db'%(output_root, sub_dir, filename)

                                key = '%s_%s_%s_%s_%s_%s_%s'%(package, arch, comp, popt, opt, lopt, filename)
                                ret.append(BuildConf(target, pickle_file, arch, popt, opt, key))

                                global_key_list.append(key)
    return ret


class Stat:
    def __init__(self, conf):
        self.target = conf.target
        self.arch = conf.arch
        self.pie = conf.pie
        self.opt = conf.opt
        self.pickle_file = conf.pickle_file
        self.key = conf.key
        self.outside = []
        self.non_func_ptr_list = []
        self.xaddr_list =[]
        self.sym_list = [0,0,0,0,0,0,0,0,0]

    def get_addr(self, factor):
        addrx = 0
        for term in factor.terms:
            if isinstance(term, int):
                continue
            addrx += term.Address
        if addrx == 0: return 0,0

        return addrx, addrx + factor.num

    def check_factor(self, asm, factor):
        self.sym_list[factor.get_type()] += 1

        if factor.get_type() in [2,4,6]:
            base, addrx = self.get_addr(factor)
            if addrx != 0:
                self.xaddr_list.append((asm, base, addrx))
        elif factor.get_type() in [1,3,5]:

            if not isinstance(asm, InstType):
                return
            if not asm.asm_token.opcode.startswith('mov') and not asm.asm_token.opcode.startswith('lea'):
                return

            base, addrx = self.get_addr(factor)
            _, sec_name = self.get_sec_name(base)
            if sec_name in ['.text']:
                if base not in self.func_list:
                    msg = '%s:%s %s : %s is not func'%(self.target, hex(asm.addr), asm.asm_line, hex(base))
                    self.non_func_ptr_list.append(msg)

    def get_func_list(self):
        output = os.popen("readelf -s %s | grep FUNC | awk '{print $2}'"%(self.target)).read()
        return [int(item,16) for item in output.split()]

    def examine(self):
        self.sec_region_list = self.get_sec_regions()
        self.func_list = self.get_func_list()

        with open(self.pickle_file, 'rb') as f:
            gt = pickle.load(f)

            for _, inst in gt.Instrs.items():
                if not isinstance(inst, InstType):
                    continue
                if inst.disp:
                    self.check_factor(inst, inst.disp)
                if inst.imm:
                    self.check_factor(inst, inst.imm)

            for _, data in gt.Data.items():
                if not isinstance(data, DataType):
                    continue
                if data.value:
                    self.check_factor(data, data.value)

            total = 0
            for nType in range(1, 8):
                total += self.sym_list[nType]

        self.sym_list[0] = total
        self.outside_check()

    def cleanup(self):
        self.sec_region_list = []
        self.xaddr_list = []


    def get_sec_regions(self):
        region_list = []
        with open(self.target, 'rb') as fp:
            elf = ELFFile(fp)
            for section in elf.iter_sections():
                 if section['sh_addr']:
                    region_list.append((section.name, range(section['sh_addr'], section['sh_addr'] + section['sh_size'])))

        return region_list

    def get_sec_name(self, addr):
        for idx, (sec_name, region) in enumerate(self.sec_region_list):
            if addr in region:
                return (idx, sec_name)
        return -1, ''

    def outside_check(self):
        for asm, base, xaddr in self.xaddr_list:
            bFound = False
            idx1, sec_name1 = self.get_sec_name(base)
            idx2, sec_name2 = self.get_sec_name(xaddr)

            if idx2 != -1:
                bFound = True

            if idx1 != idx2:
                self.outside.append('%s:%s %s [%d][from: %s -> to: %s ][ %s => %s ]'%(self.target, hex(asm.addr), asm.asm_line, bFound, hex(base), hex(xaddr), sec_name1, sec_name2))



def report(desc, sym_list, bSummary=True):
    tot = sym_list[0]
    if bSummary:
        print('%-20s : %6.3f%% %6.3f%% %6.3f%% %6.3f%% %6.3f%% %6.3f%% %6.3f%% %10d'%(desc,
            sym_list[1]/tot*100, sym_list[2]/tot*100, sym_list[3]/tot*100, sym_list[4]/tot*100,
            sym_list[5]/tot*100, sym_list[6]/tot*100, sym_list[7]/tot*100, sym_list[0]))
    else:
        print('%-70s : %6.3f%% %6.3f%% %6.3f%% %6.3f%% %6.3f%% %6.3f%% %6.3f%% %10d'%(desc,
            sym_list[1]/tot*100, sym_list[2]/tot*100, sym_list[3]/tot*100, sym_list[4]/tot*100,
            sym_list[5]/tot*100, sym_list[6]/tot*100, sym_list[7]/tot*100, sym_list[0]))


def job(conf):
    stat = Stat(conf)
    stat.examine()
    stat.cleanup()

    with open('stat/%s'%(conf.key), 'wb') as f:
        pickle.dump(stat, f)


class Manager:

    def __init__(self, input_root='./dataset', output_root='./output'):
        self.stat_list = []
        self.input_root=input_root
        self.output_root=output_root
        self.config_list = gen_option(self.input_root, self.output_root)

    def run(self, core=1):

        if core and core > 1:
            p = multiprocessing.Pool(core)
            p.map(job, self.config_list)
        else:
            for conf in self.config_list:
                job(conf)



    def init_summary(self):
        data = dict()
        data['x64'] = dict()
        data['x86'] = dict()
        data['x64']['pie'] = [0,0,0,0,0,0,0,0,0]
        data['x64']['nopie'] = [0,0,0,0,0,0,0,0,0]
        data['x86']['pie'] = [0,0,0,0,0,0,0,0,0]
        data['x86']['nopie'] = [0,0,0,0,0,0,0,0,0]
        data['o0'] = [0,0,0,0,0,0,0,0,0]
        data['o1'] = [0,0,0,0,0,0,0,0,0]
        data['o2'] = [0,0,0,0,0,0,0,0,0]
        data['o3'] = [0,0,0,0,0,0,0,0,0]
        data['os'] = [0,0,0,0,0,0,0,0,0]
        data['ofast'] = [0,0,0,0,0,0,0,0,0]
        data['total'] = [0,0,0,0,0,0,0,0,0]
        return data


    def summary(self, verbose):

        global global_key_list

        if verbose:
            print('%-70s : %7s %7s %7s %7s %7s %7s %7s %10s'%('',
                    'Type1', 'Type2','Type3', 'Type4',
                    'Type5', 'Type6','Type7', 'Total'))

        num_of_bin_has_comp = 0
        summary = self.init_summary()

        outside_dict = dict()
        nonfunc_dict = dict()
        for key in global_key_list:
            with open('stat/%s'%(key), 'rb') as f:
                stat = pickle.load(f)

                if verbose:
                    report(stat.target, stat.sym_list, bSummary = False)

                summary[stat.opt] = np.add(summary[stat.opt], stat.sym_list)
                summary[stat.arch][stat.pie] = np.add(summary[stat.arch][stat.pie], stat.sym_list)

                if stat.sym_list[2] + stat.sym_list[4] + stat.sym_list[6] + stat.sym_list[7] > 0:
                    num_of_bin_has_comp += 1

                if stat.outside:
                    outside_dict[stat.target] = stat.outside

                if stat.non_func_ptr_list:
                    nonfunc_dict[stat.target] = stat.non_func_ptr_list

        print('-------- Arch + PIE options --------')
        print('%-20s : %7s %7s %7s %7s %7s %7s %7s %10s'%('',
                    'Type1', 'Type2','Type3', 'Type4',
                    'Type5', 'Type6','Type7', 'Total'))

        for arch in ['x86', 'x64']:
            for pie in ['nopie', 'pie']:
                desc = '%s-%s'%(arch, pie)
                report(desc, summary[arch][pie])

        print('-------- Optimizations --------')
        for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
            summary['total'] = np.add(summary['total'], summary[opt])
            report(opt, summary[opt])

        report('total', summary['total'])



        print('-------- Atomic vs. Composite --------')
        for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
            atomic = summary[opt][1] + summary[opt][3] + summary[opt][5]
            composite = summary[opt][2] + summary[opt][4] + summary[opt][6] + summary[opt][7]
            total = atomic + composite
            print('%-20s:  %6.3f%% (%10d / %10d) relocation expressions are composite'%(opt, composite/total*100, composite, total))


        atomic = summary['total'][1] + summary['total'][3] + summary['total'][5]
        composite = summary['total'][2] + summary['total'][4] + summary['total'][6] + summary['total'][7]
        total = atomic + composite
        print('%-20s:  %6.3f%% (%10d / %10d) relocation expressions are composite'%('Total', composite/total*100, composite, total))

        print('Total %6.3f%% (%5d/%5d) binaries have composite relocs!'%(
            num_of_bin_has_comp/len(global_key_list) * 100 , num_of_bin_has_comp, len(global_key_list)))


        print('-------- point to outside --------')
        print('%6.3f%% (%5d/%5d) binaries have composite relocs that point to outside'%(
            len(outside_dict)/len(global_key_list) * 100, len(outside_dict), len(global_key_list)))
        if verbose:
            for key, value in outside_dict.items():
                print('%-60s: %d'%(key, len(value)))
                for msg in value:
                    print(msg)

        print('-------- point to non-func --------')
        print('%6.3f%% (%5d/%5d) binaries have code pointers that point to non-function entries'%(
            len(nonfunc_dict)/len(global_key_list) * 100, len(nonfunc_dict), len(global_key_list)))
        if verbose:
            for key, value in nonfunc_dict.items():
                print('%-80s: %d'%(key, len(value)))
                for msg in value:
                    print(msg)

import argparse
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--package', type=str, help='Package')
    parser.add_argument('--core', type=int, default=1, help='Number of cores to use')
    parser.add_argument('--skip', action='store_true')
    parser.add_argument('--verbose', action='store_true')

    args = parser.parse_args()

    mgr = Manager()

    if not args.skip:
        os.system('mkdir -p ./stat')
        if args.core:
            mgr.run(args.core)
        else:
            mgr.run()

    mgr.summary(args.verbose)
