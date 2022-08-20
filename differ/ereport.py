from collections import namedtuple
import pickle
import os
import json
from lib.types import CmptTy, InstType, DataType, ReportTy
from enum import Enum

ERec = namedtuple('ERec', ['record', 'gt'])
EData = namedtuple('EData', ['address', 'asm_info', 'reasm_info', 'region', 'gt_asm', 'tool_asm', 'tool_reloc_type', 'invalid_label', 'label_addr1', 'label_addr2', 'criticality'])

class ErrorType(Enum):
    TP=0
    FN=1
    SAFE_FP=0
    CLASSIC_FP=2
    LABEL_UNDEF=3
    LABEL_DUP=4
    LABEL_SEMANTICS=5
    DIFF_ADDRS=6
    DIFF_SECTIONS=7
    CODE_REGION=8
    DIFF_BASES=9
    UNDEF=10

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

        self.adata = []

    def add(self, gt_factor, tool_factor, region, tool_reloc_type, invalid_label=0, label_addr1=0, label_addr2=0, criticality=ErrorType.UNDEF):

        if gt_factor:
            address     = gt_factor.addr
            asm_info    = gt_factor.path,    gt_factor.asm_idx
            gt_asm      = gt_factor.asm_line.strip()
        else:
            address     = tool_factor.addr
            asm_info    = None
            gt_asm      = None

        #reasm_type = 0
        if tool_factor:
            reasm_info  = tool_factor.path,  tool_factor.asm_idx
            tool_asm    = tool_factor.asm_line.strip()
        else:
            reasm_info  = None
            tool_asm    = None


        self.adata.append(EData(address, asm_info, reasm_info, region,
                                gt_asm, tool_asm, tool_reloc_type,
                                invalid_label, label_addr1, label_addr2,
                                criticality))

    def dump(self, out_file):

        for (addr, asm_info, reasm_info, region, gt_asm, tool_asm, tool_reloc_type, invalid_label, label_addr1, label_addr2, criticality) in sorted(self.adata):
            gt = ''
            if asm_info:
                gt = gt_asm
            tool = ''
            if reasm_info:
                tool = tool_asm
            if invalid_label == 3:
                print('E%d%2s [%d] (%4s:%d:%d) %-8s: %-40s  | %-44s (ADDR: %s vs %s)'%(self.stype, self.etype, criticality.value, region, tool_reloc_type, invalid_label, hex(addr), tool, gt, hex(label_addr2), hex(label_addr1)), file=out_file)
            elif criticality == ErrorType.DIFF_ADDRS:
                print('E%d%2s [%d] (%4s:%d:%d) %-8s: %-40s  | %-44s (ADDR: %s vs %s)'%(self.stype, self.etype, criticality.value, region, tool_reloc_type, invalid_label, hex(addr), tool, gt, hex(label_addr2), hex(label_addr1)), file=out_file)
            else:
                print('E%d%2s [%d] (%4s:%d:%d) %-8s: %-40s  | %-40s'%(self.stype, self.etype, criticality.value, region, tool_reloc_type, invalid_label, hex(addr), tool, gt), file=out_file)

    def length(self):
        return len(self.adata)

    def critical_errors(self):
        return len([item for item in self.adata if item.criticality])


class RecS:
    def __init__(self, stype):
        self.stype = stype
        self.fp = Record(stype, 'FP')
        self.fn = Record(stype, 'FN')
        self.tp = 0

    def dump(self, out_file):
        if 0 == self.fp.length() + self.fn.length():
            return

        num_fp = self.fp.length()
        num_critical_fp = self.fp.critical_errors()
        num_fn = self.fn.length()
        print('Relocatable Expression Type %d [FP: %d(%d) / FN: %d]'%(self.stype, num_fp, num_critical_fp, num_fn), file = out_file)
        self.fp.dump(out_file)
        self.fn.dump(out_file)


class Report:
    def __init__(self, bin_path, prog_c):

        self.excluded_data_list, self.included_region_list = self.check_data_region(bin_path)

        self.prog_c = prog_c
        self.gt = 0

        self.rec = dict()
        for stype in range(1, 9):
            self.rec[stype] = RecS(stype)

    def check_data_region(self, bin_path):
        ex_region_list = []
        inc_region_list = []
        with open(bin_path, 'rb') as fp:
            from elftools.elf.elffile import ELFFile
            elf = ELFFile(fp)
            for section in elf.iter_sections():
                is_rela = False
                try:
                    is_rela = section._is_rela
                except:
                    is_rela = False
                #if section.name in ['.rela.plt', '.rel.plt', '.rel.dyn', '.rela.dyn']:
                if is_rela:
                    ex_region_list.append(range(section['sh_addr'], section['sh_addr'] + section['sh_size']))
                elif section['sh_size'] > 0:
                    inc_region_list.append((range(section['sh_addr'], section['sh_addr'] + section['sh_size']), section.name))

        return ex_region_list, inc_region_list

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

            if addr in self.prog_c.Data:
                data_c = self.prog_c.Data[addr]
                if data_c.r_type and data_c.r_type in ['R_X86_64_GLOB_DAT', 'R_X86_64_JUMP_SLOT']:
                    continue
                elif data_c.r_type and data_c.r_type in ['R_386_GLOB_DAT','R_386_JUMP_SLOT']:
                    continue

            if addr in self.prog_c.Data and addr in prog_r.Data: # TP or FP
                data_c = self.prog_c.Data[addr]
                data_r = prog_r.Data[addr]
                self.check_data_error(data_c, data_r, addr)
            elif addr in self.prog_c.Data: # FN
                data_c = self.prog_c.Data[addr]
                self.check_data_error(data_c, None, addr)
            elif addr in prog_r.Data: # FP
                # we couldn't decide label-relative addressing
                # since its reloc info would not be defined in relocation table
                data_r = prog_r.Data[addr]

                if not self.is_in_data_region(addr):
                    continue
                if data_r.value.type == 7:
                    continue
                self.check_data_error(None, data_r, addr)

    def is_in_data_region(self, addr):
        for region in self.excluded_data_list:
            if addr in region:
                return False
        return True

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

                        if (tool_reloc.terms[0].Address > 0 and
                            (gt_reloc.terms[0].Address != (tool_reloc.terms[0].Address+tool_reloc.terms[0].Num))):
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

        if result == ReportTy.FP:
            if gt_reloc is None:
                criticality = ErrorType.CLASSIC_FP
            elif invalid_label == 1:
                criticality = ErrorType.LABEL_UNDEF
            elif invalid_label == 2:
                criticality = ErrorType.LABEL_DUP
            else:
                criticality = self.check_fp_criticality(gt_reloc, tool_reloc)
                if invalid_label != 3 and criticality == ErrorType.DIFF_ADDRS:
                    label_addr1 = gt_reloc.terms[0].Address + gt_reloc.num
                    label_addr2 = (tool_reloc.terms[0].Address + tool_reloc.terms[0].Num ) + tool_reloc.num

                if tool_reloc.terms[0].Num:
                    invalid_label = 4 # composite .set label

        elif result == ReportTy.FN:
            criticality = ErrorType.FN
        else: # TP
            criticality = ErrorType.TP

        self.record_result(region, result, gt_reloc_type, tool_reloc_type, gt_factor, tool_factor, invalid_label, label_addr1, label_addr2, criticality)

    def get_sec_name(self, addr):
        for region, sec_name in self.included_region_list:
            if addr in region:
                return sec_name

        return 'unknown'

    def check_fp_criticality(self, gt_reloc, tool_reloc):

        # check types
        if gt_reloc.type == 7 and tool_reloc.type == 7:
            #print('invalid type 7')
            return ErrorType.DIFF_BASES

        if gt_reloc.type != tool_reloc.type:
            if int((gt_reloc.type-1)/2) != int((tool_reloc.type-1)/2):
                #print('different semantics')
                return ErrorType.LABEL_SEMANTICS #diff semantics
        '''
        else:
            if gt_reloc.type in [1,3,5]:
                #print('different atomic relocatable expressions')
                #return ErrorType.DIFF_ADDRS #diff addr
        '''

        # check target addresses
        if (gt_reloc.terms[0].Address+gt_reloc.num) != ((tool_reloc.terms[0].Address+tool_reloc.terms[0].Num) +tool_reloc.num):
            return ErrorType.DIFF_ADDRS #diff addr

        # check target section
        sec1 = self.get_sec_name(gt_reloc.terms[0].Address)
        sec2 = self.get_sec_name(tool_reloc.terms[0].Address)

        # if two target point to same data region, it can be considered as non-critical!!!!
        if sec1 != sec2:
            return ErrorType.DIFF_SECTIONS #diff section

        if sec1 in ['.text', '.init', '.fini', '.plt']:
            return ErrorType.CODE_REGION #text section

        # non-critical FP
        return ErrorType.SAFE_FP



    def record_result(self, region, result, gt_reloc_type, tool_reloc_type, gt_factor, tool_factor, invalid_label, label_addr1, label_addr2, criticality):
        if result == ReportTy.TP:
            self.rec[gt_reloc_type].tp += 1
        elif result == ReportTy.FP:
            self.rec[gt_reloc_type].fp.add(gt_factor, tool_factor, region, tool_reloc_type, invalid_label, label_addr1, label_addr2, criticality)
        elif result == ReportTy.FN:
            self.rec[gt_reloc_type].fn.add(gt_factor, tool_factor, region, tool_reloc_type, criticality=ErrorType.FN)


    def check_data_error(self, data_c, data_r, addr):
        self.gt += 1
        if data_c and data_r is None:
            # this is reassembler design choice
            # ddisasm preserve .got section
            # retrowrite delete .got section
            # Thus, we do not check this case
            if data_c.r_type and data_c.r_type in ['R_X86_64_GLOB_DAT', 'R_X86_64_JUMP_SLOT']:
                pass
            elif data_c.r_type and data_c.r_type in ['R_386_GLOB_DAT','R_386_JUMP_SLOT']:
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


