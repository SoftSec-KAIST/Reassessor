import os, pickle, glob
from elftools.elf.elffile import ELFFile

class Manager:

    def __init__(self, bench='./dataset', out='./output'):
        self.bench = bench
        self.out = out

    def get_addr(self, factor):
        addrx = 0
        for term in factor.terms:
            if isinstance(term, int):
                continue
            addrx += term.Address
        if addrx == 0: return 0,0

        return addrx, addrx + factor.num

    def get_pickle_path(self, target):
        filename = os.path.basename(target)
        sub_dir = '/'.join(target.split('/')[-7:-2])
        (package, arch, comp, pie_opt, lopt) = sub_dir.split('/')
        assert package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006'], 'invalid package'

        pickle_path = '%s/%s/%s/norm_db/gt.db'%(self.out, sub_dir, filename)
        return pickle_path


    def get_sec_regions(self, target):
        region_list = []
        with open(target, 'rb') as fp:
            elf = ELFFile(fp)
            for section in elf.iter_sections():
                 if section['sh_addr']:
                    region_list.append((section.name, range(section['sh_addr'], section['sh_addr'] + section['sh_size'])))


        return region_list


    def run(self):
        target_list = []
        for pack in ['spec_cpu2006', 'binutils-2.31.1', 'coreutils-8.30']:
            for arch in ['x86', 'x64']:
                for comp in ['clang', 'gcc']:
                    for popt in ['pie', 'nopie']:
                        for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                            for lopt in ['gold', 'bfd']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)

                                for binary in glob.glob('%s/%s/reloc/*'%(self.bench, sub_dir)):
                                    filename = os.path.basename(binary)
                                    target_list.append(binary)

        for target in target_list:
            self.single_run(target)


    def single_run(self, target):

        path = os.path.dirname(target)
        my_pickle = self.get_pickle_path(target)
        sec_region_list = self.get_sec_regions(target)

        with open(my_pickle, 'rb') as fp:
            rec = pickle.load(fp)

            xaddr_list = []
            for addr in rec.Instrs:
                asm = rec.Instrs[addr]
                if asm.disp:
                    if asm.disp.get_type() in [2,4,6]:
                        base, addrx = self.get_addr(asm.disp)
                        if addrx != 0:
                            xaddr_list.append((asm, base, addrx))
                if asm.imm:
                    if asm.imm.get_type() in [2,4,6]:
                        base, addrx = self.get_addr(asm.imm)
                        if addrx != 0:
                            xaddr_list.append((asm, base, addrx))
            for addr in rec.Data:
                data = rec.Data[addr]
                if data.value:
                    if data.value.get_type() in [2,4,6]:
                        base, addrx = self.get_addr(data.value)
                        if addrx != 0:
                            xaddr_list.append((asm, base, addrx))

            for asm, base, xaddr in xaddr_list:
                bFound = False
                region1 = -1
                region2 = -1
                sec_name1 = ''
                sec_name2 = ''
                for idx, (sec_name, region) in enumerate(sec_region_list):
                    if base in region:
                        region1 = idx
                        sec_name1 = sec_name
                for idx, (sec_name, region) in enumerate(sec_region_list):
                    if xaddr in region:
                        region2 = idx
                        bFound = True
                        sec_name2 = sec_name

                if region1 != region2:
                    print('%s:%s %s [%d][from: %s -> to: %s ][ %s => %s ]'%(target, hex(asm.addr), asm.asm_line, bFound, hex(base), hex(xaddr), sec_name1, sec_name2))


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
