from collections import namedtuple
import pickle
import os
import json
from lib.types import CmptTy, InstType, DataType, ReportTy

ERec = namedtuple('ERec', ['record', 'gt'])

def my_open(file_path, option='w'):
     if 'w' in option:
         dir_name = os.path.dirname(file_path)
         if not os.path.exists(dir_name):
             os.system("mkdir -p %s" % dir_name)
     fd = open(file_path, option)
     return fd

class Record:
    def __init__(self, stype, etype):
        self.stype = stype      #1-8
        self.etype = etype      #FP/FN

        self.jdata = []
        self.adata = []

    def add(self, gt, tool, region, tool_reloc_type, invalid_label=0, label_addr1=0, label_addr2=0):
        if gt:
            address     = gt.addr
            asm_info    = gt.path,    gt.asm_idx
            gt_asm      = gt.asm_line.strip()
        else:
            address     = tool.addr
            asm_info    = None
            gt_asm      = None

        #reasm_type = 0
        if tool:
            reasm_info  = tool.path,  tool.asm_idx
            tool_asm    = tool.asm_line.strip()
        else:
            reasm_info  = None
            tool_asm    = None


        self.adata.append((address, asm_info, reasm_info, region, gt_asm, tool_asm, tool_reloc_type, invalid_label, label_addr1, label_addr2))

    def dump(self, out_file):

        for (addr, asm_info, reasm_info, region, gt_asm, tool_asm, tool_reloc_type, invalid_label, label_addr1, label_addr2) in sorted(self.adata):
            gt = ''
            if asm_info:
                gt = gt_asm
            tool = ''
            if reasm_info:
                tool = tool_asm
            if invalid_label == 3:
                print('E%d%2s (%4s:%d:%d) %-8s: %-40s  | %-40s (ADDR: %s vs %s)'%(self.stype, self.etype, region, tool_reloc_type, invalid_label, hex(addr), tool, gt, hex(label_addr2), hex(label_addr1)), file=out_file)
            else:
                print('E%d%2s (%4s:%d:%d) %-8s: %-40s  | %-40s'%(self.stype, self.etype, region, tool_reloc_type, invalid_label, hex(addr), tool, gt), file=out_file)

    def length(self):
        return len(self.adata)


class RecS:
    def __init__(self, stype):
        self.stype = stype
        self.fp = Record(stype, 'FP')
        self.fn = Record(stype, 'FN')
        self.tp = 0

    def dump(self, out_file):
        if 0 == self.fp.length() + self.fn.length():
            return

        print('Relocatable Expression Type %d'%(self.stype), file = out_file)
        self.fp.dump(out_file)
        self.fn.dump(out_file)


    def get_json(self):
        res = []
        res.extend(self.fp.jdata)
        res.extend(self.fp.jdata)
        res.extend(self.fn.jdata)
        res.extend(self.fn.jdata)
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
                self.check_data_error(data_c, data_r, addr)
            elif addr in self.prog_c.Data: # FN
                data_c = self.prog_c.Data[addr]
                self.check_data_error(data_c, None, addr)
            elif addr in prog_r.Data: # FP
                data_r = prog_r.Data[addr]
                self.check_data_error(None, data_r, addr)



    def compare_ins_errors(self, prog_r):

        ins_addrs_c = set(self.prog_c.Instrs.keys())
        ins_addrs_r = set(prog_r.Instrs.keys())
        ins_addrs = ins_addrs_c.intersection(ins_addrs_r)

        self.ins_len = len(ins_addrs)

        for addr in ins_addrs:
            ins_c = self.prog_c.Instrs[addr]
            ins_r = prog_r.Instrs[addr]

            if ins_c.imm or ins_c.disp or ins_r.imm or ins_r.disp:
                self.check_ins(ins_c, ins_r, addr)

        fn = ins_addrs_c - ins_addrs_r
        for addr in fn:
            ins_c = self.prog_c.Instrs[addr]

            if ins_c.imm or ins_c.disp:
                self.check_ins(ins_c, None, addr)

        fp = ins_addrs_r - ins_addrs_c - self.prog_c.unknown_region
        for addr in fp:
            ins_r = prog_r.Instrs[addr]
            if ins_r.imm or ins_r.disp:
                self.check_ins(None, ins_r, addr)

    def compare_two_reloc_expr(self, gt_factor, tool_factor, region, addr):
        gt_reloc = None
        tool_reloc = None
        if gt_factor:
            if region == 'Imm':
                gt_reloc = gt_factor.imm
            elif region == 'Disp':
                gt_reloc = gt_factor.disp
            elif region == 'Data':
                gt_reloc = gt_factor.value
        if tool_factor:
            if region == 'Imm':
                tool_reloc = tool_factor.imm
            elif region == 'Disp':
                tool_reloc = tool_factor.disp
            elif region == 'Data':
                tool_reloc = tool_factor.value

        gt_reloc_type = 8
        tool_reloc_type = 8

        invalid_label = 0
        result = ReportTy.UNKNOWN
        label_addr1 = 0
        label_addr2 = 0

        if gt_reloc:
            gt_reloc_type = gt_reloc.type
            label_addr1 = gt_reloc.terms[0].Address
        if tool_reloc:
            tool_reloc_type = tool_reloc.type
            label_addr2 =  tool_reloc.terms[0].Address

            if tool_reloc.terms[0].Address < 0:
                # -1: does not exist
                # -2: duplicated label
                invalid_label = abs(tool_reloc.terms[0].Address)


        if gt_reloc and tool_reloc:
            if gt_reloc_type == tool_reloc.type:
                if gt_reloc_type in [7]:
                    if gt_reloc.terms[0].get_value() == tool_reloc.terms[0].get_value() and gt_reloc.terms[1].get_value() == tool_reloc.terms[1].get_value():
                        result = ReportTy.TP
                    else:
                        result = ReportTy.FP

                else: # gt_reloc_type in [1,2,3,4,5,6]:

                    if gt_reloc_type in [2,4,6] and gt_reloc.num != tool_reloc.num:
                        result = ReportTy.FP

                    # if valiable is defined with suffix @GOT, compiler will allocate memory region.
                    elif '@GOT' in tool_reloc.terms[0].get_name() and tool_reloc.terms[0].get_name().split('@')[1] == 'GOT':
                        result = ReportTy.TP

                    #  Address == 0: Reloc Symbol (Unknown symbol)
                    elif ( gt_reloc.terms[0].Address != 0 and
                         tool_reloc.terms[0].Address != 0 and
                         gt_reloc.terms[0].Address != tool_reloc.terms[0].Address):

                        result = ReportTy.FP

                        if tool_reloc.terms[0].Address > 0:
                            invalid_label = 3 # label address is diffent
                            #print('>> %s (%d): %s vs %s'%(hex(addr), gt_reloc_type, hex(gt_reloc.terms[0].Address), hex(tool_reloc.terms[0].Address)))
                            #print('>>>>' , tool_factor.asm_line)

                    else:
                        result = ReportTy.TP

            else:
                result = ReportTy.FP

        elif gt_reloc:
            result = ReportTy.FN

        elif tool_reloc:
            result = ReportTy.FP

        self.record_result(region, result, gt_reloc_type, tool_reloc_type, gt_factor, tool_factor, invalid_label, label_addr1, label_addr2)

    def record_result(self, region, result, gt_reloc_type, tool_reloc_type, gt_factor, tool_factor, invalid_label, label_addr1, label_addr2):
        if result == ReportTy.TP:
            self.rec[gt_reloc_type].tp += 1
        elif result == ReportTy.FP:
            self.rec[gt_reloc_type].fp.add(gt_factor, tool_factor, region, tool_reloc_type, invalid_label, label_addr1, label_addr2)
        elif result == ReportTy.FN:
            self.rec[gt_reloc_type].fn.add(gt_factor, tool_factor, region, tool_reloc_type)


    def check_data_error(self, data_c, data_r, addr):
        self.gt += 1
        if data_c and data_r is None:
            # this is reassembler design choice
            # ddisasm preserve .got section
            # retrowrite delete .got section
            # Thus, we do not check this case
            if data_c.r_type and data_c.r_type in ['R_X86_64_GLOB_DAT']:
                pass
            elif data_c.r_type and data_c.r_type in ['R_X86_64_JUMP_SLOT']:
                pass
            else:
                self.compare_two_reloc_expr(data_c, data_r, 'Data', addr)
        else:
            self.compare_two_reloc_expr(data_c, data_r, 'Data', addr)


    def check_ins(self, ins_c, ins_r, addr):
        self.gt += 1

        self.compare_two_reloc_expr(ins_c, ins_r, 'Imm', addr)
        self.compare_two_reloc_expr(ins_c, ins_r, 'Disp', addr)

    def save_pickle(self, file_path):
        with my_open(file_path, 'wb') as fd:
            data = ERec(self.rec, self.gt)
            pickle.dump(data, fd)

    def save_file(self, file_path, option='ascii'):
        with my_open(file_path, 'w') as fd:
            if option == 'ascii':
                self.save_ascii_file(fd)
            else:
                raise SyntaxError("Unsupported save format")

    def save_ascii_file(self, out_file):
        print('# Instrs to check:', self.ins_len, file = out_file)
        print('# Data to check:', self.data_len, file = out_file)
        for stype in range(1,9):
            self.rec[stype].dump(out_file)


