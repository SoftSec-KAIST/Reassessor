from collections import namedtuple
import pickle
import os
import json
from lib.asm_types import CmptTy

ERec = namedtuple('ERec', ['record', 'gt'])

def my_open(file_path, option='w'):
     if 'w' in option:
         dir_name = os.path.dirname(file_path)
         if not os.path.exists(dir_name):
             os.system("mkdir -p %s" % dir_name)
     fd = open(file_path, option)
     return fd

class Record:
    def __init__(self, stype, etype, region):
        self.stype = stype      #1-8
        self.etype = etype      #FP/FN
        self.region = region    #Ins/Data

        self.jdata = []
        self.adata = []

    def add(self, gt, tool, loc):
        if gt:
            address     = gt.addr
            src_gt      = gt.path,    gt.asm_idx
            gt_asm      = gt.asm_line
        else:
            address     = tool.addr
            src_gt      = None
            gt_asm      = None

        if tool:
            src_tool    = tool.path,  tool.asm_idx
            tool_asm    = tool.asm_line
        else:
            src_tool    = None
            tool_asm    = None

        #info = Info(self.stype, address, self.region, self.etype, gt,  tool, src_gt, src_tool, loc)

        #self.jdata.append(info.to_json())
        #self.adata.append((address, self.region, self.etype, src_gt, src_tool, idx))
        self.adata.append((address, self.region, self.etype, src_gt, src_tool, loc, gt_asm, tool_asm))

    def dump(self, out_file):

        for (addr, ty, res, src_c, src_r, loc, gt_asm, tool_asm) in sorted(self.adata):
            print('T%d'%(self.stype), hex(addr), ty, res, src_c, src_r, loc, file = out_file)
            if src_c:
                print('\tGT:   %s'%(gt_asm), file=out_file)
            if src_r:
                print('\tTOOL: %s'%(tool_asm), file=out_file)

class RecE:
    def __init__(self, stype, etype):
        self.stype = stype
        self.etype = etype
        self.ins = Record(stype, etype, 'Ins')
        self.data = Record(stype, etype, 'Data')

    def length(self):
        return len(self.ins.adata) + len(self.data.adata)

    def dump(self, out_file):
        self.ins.dump(out_file)
        self.data.dump(out_file)

class RecS:
    def __init__(self, stype):
        self.stype = stype
        self.fp = RecE(stype, 'FP')
        self.fn = RecE(stype, 'FN')
        self.tp = 0

    def dump(self, out_file):
        if 0 == self.fp.length() + self.fn.length():
            return

        print('Type %d'%(self.stype), file = out_file)
        self.fp.dump(out_file)
        self.fn.dump(out_file)


    def get_json(self):
        res = []
        res.extend(self.fp.ins.jdata)
        res.extend(self.fp.data.jdata)
        res.extend(self.fn.ins.jdata)
        res.extend(self.fn.data.jdata)
        return res

class Report:
    def __init__(self, prog_c):
        self.prog_c = prog_c
        self.gt = 0

        self.rec = dict()
        for stype in range(1, 9):
            self.rec[stype] = RecS(stype)

    def compare(self, prog_r):
        #self.reset()
        self.compare_ins_errors(prog_r)
        self.compare_data_errors(prog_r)


    def compare_data_errors(self, prog_r):
        data_addrs_c = set(self.prog_c.Data.keys())
        data_addrs_r = set(prog_r.Data.keys())
        data_addrs = data_addrs_c.union(data_addrs_r)

        self.data_len = len(data_addrs)
        for addr in data_addrs:
            if addr in self.prog_c.Data and addr in prog_r.Data: # TP or FP
                data_c = self.prog_c.Data[addr]
                data_r = prog_r.Data[addr]
                self.check_data_error(data_c, data_r)
            elif addr in self.prog_c.Data: # FN
                data_c = self.prog_c.Data[addr]
                self.check_data_error(data_c, None)
            elif addr in prog_r.Data: # FP
                data_r = prog_r.Data[addr]
                self.rec[8].fp.data.add(None, data_r, 'value')



    def compare_ins_errors(self, prog_r):

        ins_addrs_c = set(self.prog_c.Instrs.keys())
        ins_addrs_r = set(prog_r.Instrs.keys())
        ins_addrs = ins_addrs_c.intersection(ins_addrs_r)

        self.ins_len = len(ins_addrs)

        for addr in ins_addrs:
            ins_c = self.prog_c.Instrs[addr]
            ins_r = prog_r.Instrs[addr]

            if ins_c.imm or ins_c.disp or ins_r.imm or ins_r.disp:
                self.check_ins(ins_c, ins_r)

        fn = ins_addrs_c - ins_addrs_r
        for addr in fn:
            ins_c = self.prog_c.Instrs[addr]
            data_r = None
            if addr in prog_r.Data:
                data_r = prog_r.Data[addr]
            if ins_c.imm:
                self.rec[ins_c.imm.type].fn.ins.add(ins_c, data_r, 'imm')
            if ins_c.disp:
                self.rec[ins_c.disp.type].fn.ins.add(ins_c, data_r, 'disp')

        fp = ins_addrs_r - ins_addrs_c - self.prog_c.unknown_region
        for addr in fp:
            ins_r = prog_r.Instrs[addr]
            if ins_r.imm:
                self.rec[8].fp.ins.add(None, ins_r, 'imm')
            if ins_r.disp:
                self.rec[8].fp.ins.add(None, ins_r, 'disp')



    def check_ins(self, ins_c, ins_r):
        self.gt += 1

        if ins_c.imm and ins_r.imm:
            if ins_c.imm.type == ins_r.imm.type:
                self.rec[ins_c.imm.type].tp += 1
            else:
                self.rec[ins_c.imm.type].fp.ins.add(ins_c, ins_r, 'imm')
        elif ins_c.imm:
            self.rec[ins_c.imm.type].fn.ins.add(ins_c, ins_r, 'imm')
        elif ins_r.imm:
            self.rec[8].fp.ins.add(ins_c, ins_r, 'imm')


        if ins_c.disp and ins_r.disp:
            if ins_c.disp.type == ins_r.disp.type:
                self.rec[ins_c.disp.type].tp += 1
            else:
                self.rec[ins_c.disp.type].fp.ins.add(ins_c, ins_r, 'disp')
        elif ins_c.disp:
            self.rec[ins_c.disp.type].fn.ins.add(ins_c, ins_r, 'disp')
        elif ins_r.disp:
            self.rec[8].fp.ins.add(ins_c, ins_r, 'disp')


    def save_pickle(self, file_path):
        with my_open(file_path, 'wb') as fd:
            data = ERec(self.rec, self.gt)
            pickle.dump(data, fd)

    def save_file(self, file_path, option='default'):
        with my_open(file_path, 'w') as fd:
            if option == 'ascii':
                self.save_ascii_file(fd)
            elif option == 'json':
                self.save_json_file(fd)
            elif option == 'default':
                self.save_default_file(fd)
            else:
                raise SyntaxError("Unsupported save format")

    def save_ascii_file(self, out_file):
        print('# Instrs to check:', self.ins_len, file = out_file)
        print('# Data to check:', self.data_len, file = out_file)
        for stype in range(1,9):
            self.rec[stype].dump(out_file)

    def save_default_file(self, pr_file):
        for stype in range(1,9):
            print('%d,%d,%d' % (self.rec[stype].tp, self.rec[stype].fp.length(), self.rec[stype].fn.length()), file = pr_file)
        print('%d' % self.gt, file = pr_file)

    def save_json_file(self, j_file):
        res = []
        for stype in range(1,9):
            res.extend(self.rec[stype].get_json())

        print(json.dumps(res, indent=2), file = j_file)


    def check_data_error(self, data_c, data_r):
        self.gt += 1
        c_type = data_c.value.type
        if data_r is None:
            # this is reassembler design choice
            # ddisasm preserve .got section
            # retrowrite delete .got section
            # Thus, we do not check this case
            if data_c.r_type and data_c.r_type in ['R_X86_64_GLOB_DAT']:
                pass
            elif data_c.r_type and data_c.r_type in ['R_X86_64_JUMP_SLOT']:
                pass
            else:
                self.rec[c_type].fn.data.add(data_c, None, 'value')
        else:
            r_type = data_r.value.type

            if c_type == r_type:
                self.rec[c_type].tp += 1
            else:
                self.rec[c_type].fp.data.add(data_c, data_r, 'value')


