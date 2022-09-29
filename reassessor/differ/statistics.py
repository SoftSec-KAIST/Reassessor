from reassessor.lib.types import CmptTy
from .ereport import my_open
import pickle


class SymStatistics:
    def __init__(self, pickle_file):
        self.insts      = [0,0,0,0,0,0,0]
        self.data       = [0,0,0,0,0,0,0]

        with open(pickle_file, 'rb') as f:
            gt = pickle.load(f)
            self.count_symbols(gt)

    def update_symbol(self, ty, idx):
        if ty == 'ins':
            self.insts[idx-1] += 1
        else:
            self.data[idx-1] += 1


    def _count_symbol(self, factors, ty):
        if factors.has_label():
            self.update_symbol(ty, factors.type)

    def count_symbols(self, gt):
        for addr, inst in gt.Instrs.items():
            inst = gt.Instrs[addr]
            if inst.imm:
                self._count_symbol(inst.imm, 'ins')
            if inst.disp:
                self._count_symbol(inst.disp, 'ins')

        for addr, data in gt.Data.items():
            self._count_symbol(data.value, 'data')

    def save(self, output):

        with my_open(output) as fd:
            fd.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(self.insts))
            fd.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(self.data))




class Statistics:
    def __init__(self, prog_c):
        self.prog_c = prog_c
        self.reset_disasm_stat()

    def reset_disasm_stat(self):
        self.disasm     = [0,0,0]

    def count_disasm(self, prog_r, file_path):
        self.reset_disasm_stat()
        addrs_c = set(self.prog_c.Instrs.keys())
        addrs_r = set(prog_r.Instrs.keys())

        tp = addrs_c.intersection(addrs_r)
        fp = addrs_r - addrs_c - self.prog_c.unknown_region - self.prog_c.aligned_region
        fn = addrs_c - addrs_r - self.prog_c.unknown_region - self.prog_c.aligned_region

        #exclude nop region
        nop_region = set()
        for addr in fn:
            if not self.prog_c.Instrs[addr].asm_line:
                nop_region.add(addr)
            elif self.prog_c.Instrs[addr].asm_line.startswith('nop'):
                nop_region.add(addr)

        fn = fn - nop_region


        self.disasm[0] += len(tp)
        self.disasm[1] += len(fp)
        self.disasm[2] += len(fn)

        with my_open(file_path) as fd:
            fd.write('%d,%d,%d\n' % tuple(self.disasm))

            if 1000 > len(fp) + len(fn) > 0:
                self.new_diff(fd, fp, fn, self.prog_c, prog_r)
            else:
                if fp:
                    self.classic_diff(fd, fp, 'FP', prog_r)
                if fn:
                    self.classic_diff(fd, fn, 'FN', self.prog_c)

    def new_diff(self, fd, fp, fn, prog_c, prog_r):
        prev_addr = 0
        fd.write('%-8s  %-40s  | %-40s\n'%('', 'TOOL'.center(40), 'GT'.center(40)))
        fd.write('-'*100 + '\n')
        for addr in sorted(fn.union(fp)):
            if prev_addr > 0 and prev_addr + 16 < addr:
                fd.write('-'*100 + '\n')
            gt = ''
            if addr in prog_c.Instrs:
                gt = prog_c.Instrs[addr].asm_line

            tool = ''
            if addr in prog_r.Instrs:
                tool = prog_r.Instrs[addr].asm_line
            elif addr in prog_r.Data:
                tool = prog_r.Data[addr].asm_line
            fd.write('%-8s: %-40s  | %-40s\n'%(hex(addr), tool, gt))
            prev_addr = addr


    def classic_diff(self, fd, addr_set, label, prog):
        if len(addr_set) > 100:
            fd.write('%s\n'%label)
            fd.write(','.join(hex(addr) for addr in sorted(addr_set)))
            fd.write('\n')
            return
        else:
            prev_addr = 0

            for addr in sorted(addr_set):
                if prev_addr > 0 and prev_addr + 16 < addr:
                    fd.write(label + '-----'*16 + '\n')
                fd.write('%s %s: %s\n'%(label, hex(addr), prog.Instrs[addr].asm_line))
                prev_addr = addr
