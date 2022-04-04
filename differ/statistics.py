from lib.asm_types import CmptTy
from differ.ereport import my_open

class Statistics:
    def __init__(self, prog_c):
        self.prog_c = prog_c
        self.reset()

    def reset(self):
        self.reset_type_stat()
        self.reset_disasm_stat()

    def reset_type_stat(self):
        self.insts      = [0,0,0,0,0,0,0]
        self.data       = [0,0,0,0,0,0,0]
        self.instarget  = [0,0,0,0,0,0,0]

    def reset_disasm_stat(self):
        self.disasm     = [0,0,0]

    def update_symbol(self, ty, idx, in_intersect):
        if ty == 'ins':
            if in_intersect:
                self.instarget[idx-1] += 1
            self.insts[idx-1] += 1
        else:
            self.data[idx-1] += 1


    def count_cmpt_symbol(self, cmpt, ty, in_intersect):
        if cmpt.is_ms():
            if cmpt.is_composite(): # Type II, IV, VI, VII
                if cmpt.Ty == CmptTy.ABSOLUTE: # Type II
                    self.update_symbol(ty, 2, in_intersect)
                elif cmpt.Ty == CmptTy.PCREL: # Type IV
                    self.update_symbol(ty, 4, in_intersect)
                elif cmpt.Ty == CmptTy.GOTOFF: # Type VI
                    self.update_symbol(ty, 6, in_intersect)
                elif cmpt.Ty == CmptTy.OBJREL: # Type VII
                    self.update_symbol(ty, 7, in_intersect)
            else: # Type I, III, V
                if cmpt.Ty == CmptTy.ABSOLUTE: # Type I
                    self.update_symbol(ty, 1, in_intersect)
                elif cmpt.Ty == CmptTy.PCREL: # Type III
                    self.update_symbol(ty, 3, in_intersect)
                elif cmpt.Ty == CmptTy.GOTOFF: # Type V
                    self.update_symbol(ty, 5, in_intersect)

    def count_symbol(self, factors, ty, in_intersect):
        if factors.has_label():
            self.update_symbol(ty, factors.type, in_intersect)

    def count_symbols(self, prog_r, file_path):
        self.reset_type_stat()
        for addr in prog_r.Instrs:
            ins_r = prog_r.Instrs[addr]
            if ins_r.imm:
                self.count_symbol(ins_r.imm, 'ins', addr in self.prog_c.Instrs and self.prog_c.Instrs[addr].imm is not None)
            if ins_r.disp:
                self.count_symbol(ins_r.disp, 'ins', addr in self.prog_c.Instrs and self.prog_c.Instrs[addr].disp is not None)

            '''
            for idx in ins_r.get_components():
                cmpt = ins_r.Components[idx]
                if addr in self.prog_c.Instrs:
                    ins_c = self.prog_c.Instrs[addr]
                    self.count_cmpt_symbol(cmpt, 'ins', idx in ins_c.get_components())
                else:
                    self.count_cmpt_symbol(cmpt, 'ins', False)
            '''
        for addr in prog_r.Data:
            data = prog_r.Data[addr]
            #cmpt = data.Component
            #self.count_cmpt_symbol(cmpt, 'data', True)
            self.count_symbol(data.value, 'data', True)

        with my_open(file_path) as fd:
            fd.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(self.insts))
            fd.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(self.instarget))
            fd.write('%d,%d,%d,%d,%d,%d,%d\n' % tuple(self.data))

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

            if len(fp) + len(fn) < 100 and len(fp) + len(fn) > 0:
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
