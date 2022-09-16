import os, pickle, glob
from elftools.elf.elffile import ELFFile

class Manager:

    def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/bugs/gt'):
        self.bench = bench
        self.out = out

    def get_addr(self, factor):
        addrx = 0
        for term in factor.terms:
            if isinstance(term, int):
                continue
            addrx += term.Address
        if addrx == 0: return 0

        return addrx + factor.num

    def get_pickle_path(self, target):
        filename = os.path.basename(target)
        sub_dir = '/'.join(target.split('/')[-7:-2])
        (package, arch, comp, pie_opt, lopt) = sub_dir.split('/')

        pickle_path = '%s/%s/%s/norm/pickle.dat'%(self.out, sub_dir, filename)
        return pickle_path


    def get_sec_regions(self, target):
        region_list = []
        with open(target, 'rb') as fp:
            elf = ELFFile(fp)
            for section in elf.iter_sections():
                 if section['sh_addr']:
                    region_list.append(range(section['sh_addr'], section['sh_addr'] + section['sh_size']))

        return region_list


    def run(self):
        target_list = []
        for pack in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            for arch in ['x64']:
                for comp in ['clang', 'gcc']:
                    for popt in ['nopie', 'pie']:
                        for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                            for lopt in ['bfd', 'gold']:
                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                for binary in glob.glob('%s/%s/stripbin/*'%(self.bench, sub_dir)):
                                    target_list.append(binary)

        abs_rel=0
        pc_rel=0
        rel_rel = 0
        tot_gt = 0
        for target in target_list:
            rec = self.single_run_for_count(target)
            abs_rel += rec[0]
            pc_rel += rec[1]
            rel_rel += rec[2]
            tot_gt += rec[3]

        print('%8d %8d %8d %8d'%(abs_rel, pc_rel, rel_rel, tot_gt))

    def single_run_for_count(self, target):

        path = os.path.dirname(target)
        my_pickle = self.get_pickle_path(target)

        abs_rel=0
        pc_rel=0
        rel_rel = 0
        tot_gt = 0

        with open(my_pickle, 'rb') as fp:
            rec = pickle.load(fp)

            for addr in rec.Instrs:
                asm = rec.Instrs[addr]
                if asm.disp:
                    tot_gt += 1
                    if asm.disp.type in [1,2]:
                        abs_rel += 1
                    elif asm.disp.type in [3,4]:
                        pc_rel += 1
                    elif asm.disp.type in [7]:
                        rel_rel += 1
                if asm.imm:
                    tot_gt += 1
                    if asm.imm.type in [1,2]:
                        abs_rel += 1
                    elif asm.imm.type in [3,4]:
                        pc_rel += 1
                    elif asm.imm.type in [7]:
                        rel_rel += 1

            for addr in rec.Data:
                data = rec.Data[addr]
                if data.value:
                    if data.value.type in [1,2]:
                        abs_rel += 1
                    elif data.value.type in [3,4]:
                        pc_rel += 1
                    elif data.value.type in [7]:
                        rel_rel += 1


            return (abs_rel, pc_rel, rel_rel, tot_gt)



    def single_run(self, target):

        path = os.path.dirname(target)
        my_pickle = self.get_pickle_path(target)
        sec_region_list = self.get_sec_regions(target)

        with open(my_pickle, 'rb') as fp:
            rec = pickle.load(fp)

            bHasComp = False
            bHasType7 = False

            tot_gt = 0
            tot_comp = 0
            for addr in rec.Instrs:
                asm = rec.Instrs[addr]
                if asm.disp:
                    tot_gt += 1
                    if asm.disp.type in [2,4,6,7]:
                        bHasComp = True
                        tot_comp += 1
                if asm.imm:
                    tot_gt += 1
                    if asm.imm.type in [2,4,6,7]:
                        bHasComp = True
                        tot_comp += 1


            tot_data_gt = 0
            tot_data_comp = 0
            for addr in rec.Data:
                data = rec.Data[addr]
                if data.value:
                    tot_gt += 1
                    tot_data_gt += 1
                    if data.value.type in [2,4,6,7]:
                        bHasComp = True
                        tot_comp += 1
                        tot_data_comp += 1
                    if data.value.type in [7]:
                        bHasType7 = True


            print('%100s:\t(%d,%d) %8d %8d %8d %8d'%(target,bHasComp, bHasType7, tot_gt, tot_comp, tot_data_gt, tot_data_comp))


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--target', type=str)
    args = parser.parse_args()

    mgr = Manager()

    if args.target:
        mgr.single_run(args.target)
    else:
        mgr.run()
