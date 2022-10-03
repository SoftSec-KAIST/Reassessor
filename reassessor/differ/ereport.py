from collections import namedtuple
import pickle
import os
import json
from reassessor.lib.types import CmptTy, InstType, DataType, ReportTy, Label
from enum import Enum

ERec = namedtuple('ERec', ['record', 'gt', 'bin_path', 'gt_path', 'tool_path'])
EData = namedtuple('EData', ['addr', 'gt_factor', 'tool_factor', 'region', 'tool_reloc_type', 'invalid_label', 'gt_target_label', 'tool_target_label', 'criticality', 'sec_mgr'])

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
    FIXED_ADDR=10
    SEC_OUTSIDE=11
    UNDEF=12

def my_open(file_path, option='w'):
     if 'w' in option:
         dir_name = os.path.dirname(file_path)
         if not os.path.exists(dir_name):
             os.system("mkdir -p %s" % dir_name)
     fd = open(file_path, option)
     return fd

def get_expr(factor, region):
    if region == 'Imm':
        return factor.imm
    elif region == 'Disp':
        return factor.disp
    elif region == 'Data':
        return factor.value

    assert False


class SecManager:

    def __init__(self, bin_path):
        self.ex_region_list = []
        self.inc_region_list = []

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
                    self.ex_region_list.append(range(section['sh_addr'], section['sh_addr'] + section['sh_size']))
                elif section['sh_size'] > 0:
                    self.inc_region_list.append((range(section['sh_addr'], section['sh_addr'] + section['sh_size']), section.name))

    def get_sec_name(self, addr):
        if addr <= 0:
            return 'unknown'

        for region, sec_name in self.inc_region_list:
            if addr in region:
                return sec_name

        return 'unknown'

    def is_in_data_region(self, addr):
        for region in self.ex_region_list:
            if addr in region:
                return False
        return True




class ErrorRecord:
    def __init__(self, stype, etype):
        self.stype = stype
        self.etype = etype

    def to_ascii(self, data):

        err_info = self.create_dict(data)

        msg = 'E%d%2s [%d] (%4s:%d:%d) %-8s: %-40s  | %-44s'%(self.stype, self.etype,
            data.criticality.value, data.region, data.tool_reloc_type, data.invalid_label,
            err_info['addr'], err_info['tool']['asm'], err_info['gt']['asm'])

        if data.invalid_label == 3 or data.criticality == ErrorType.DIFF_ADDRS:
            msg += ' (ADDR: %s vs %s)'%(err_info['tool']['target_addr'], err_info['gt']['target_addr'])

        return msg

    def get_asm_info(self, factor):
        if factor:
            return factor.path, factor.asm_idx, factor.asm_line.strip()
        return '', 0, ''


    def create_asm_info(self, factor, sym_type, target_addr, region, sec_mgr):

        info = dict()
        info['reloc_expr_type'] = self.get_reloc_type(sym_type)
        info['target_addr'] = hex(target_addr)
        info['target_sec'] = sec_mgr.get_sec_name(target_addr)

        info['asm'] = ''
        info['path'] = ''
        info['normalize'] = ''

        if factor:
            info['asm'] = factor.asm_line.strip()
            info['path'] = '%s:%d'%(factor.path, factor.asm_idx)

            expr = get_expr(factor, region)
            if expr:
                info['normalize'] = expr.get_norm_str()
                for idx, term in enumerate(expr.terms):
                    if isinstance(term, Label):
                        info['label%d_sec'%(idx+1)] = sec_mgr.get_sec_name(term.Address)


        return info

    def create_dict(self, data):

        rec = dict()

        #addr, gt_factor, tool_factor, region, tool_reloc_type, invalid_label, gt_target_label, tool_target_label, criticality  = data

        rec['addr'] = hex(data.addr)
        rec['section'] = data.sec_mgr.get_sec_name(data.addr)

        rec['region'] = self.get_region(data.region) #value, disp, imm
        rec['fatality'] = self.get_fatality(data.criticality, data.invalid_label)

        rec['gt'] = self.create_asm_info(data.gt_factor, self.stype, data.gt_target_label, data.region, data.sec_mgr)
        rec['tool'] = self.create_asm_info(data.tool_factor, data.tool_reloc_type, data.tool_target_label, data.region, data.sec_mgr)

        return rec

    def get_fatality(self, criticality, invalid_label):
        mydict = dict()
        mydict['is_fatal'] = True

        mydict['description1'] = self.get_description(criticality)
        mydict['description2'] = self.get_label_style(invalid_label)

        if not mydict['description1']:
            mydict['is_fatal'] = False
        return mydict

    def get_description(self, criticality):
        if self.etype == 'FN':
            return 'omit symbolization'
        elif self.etype ==  'FP':
            if self.stype in [1,2,3,4,5,6,7]:
                if criticality == ErrorType.SAFE_FP:
                    return ''
                elif criticality in [ErrorType.LABEL_SEMANTICS, ErrorType.DIFF_ADDRS, ErrorType.DIFF_BASES]:
                    return 'The relocatable expression in a_r refers to a wrong addr'
                elif criticality in [ErrorType.DIFF_SECTIONS]:
                    return 'The relocatable expression in a_r refers to a different section'
                elif criticality in [ErrorType.SEC_OUTSIDE]:
                    return 'The relocatable expression in a_c refers to outside of a section'
                elif criticality in [ErrorType.CODE_REGION]:
                    return 'The different relocatable expression in a_r refers to code region'
                elif criticality in [ErrorType.FIXED_ADDR]:
                    return 'The relocatable expression in a_r uses the label that refers to a fixed addr'
                else:
                    assert False, 'Unknown FP'
            elif self.stype in [8]:
                return 'The relocatable expression in a_r corrupts data'

        assert False, 'Unknown Error'




    def get_region(self, region):
        if region == 'Disp':
            return 'Code.disp'
        elif region == 'Imm':
            return 'Code.imm'
        elif region == 'Data':
            return 'Data.value'


    def get_reloc_type(self, reloc_type):
        if reloc_type in [1,2,3,4,5,6,7]:
            return 'Type %d'%(reloc_type)
        return 'Literal'

    def get_label_style(self, label):
        if label == 1:
            return 'The definition of label in a_r does not exist'
        elif label == 2:
            return 'The label in a_r has multiple definitions'
        elif label == 3:
            return 'The target address of relocatable expression in a_r is wrong'
        elif label == 4:
            return 'The label in a_r is defined by .set directive'
        elif label == 5:
            return 'The label in a_r is defined as a fixed address'

        return ''



class Record:
    def __init__(self, stype, etype, sec_mgr):
        self.stype = stype      #1-8
        self.etype = etype      #FP/FN
        self.sec_mgr = sec_mgr

        self.adata = []

    def add(self, gt_factor, tool_factor, region, tool_reloc_type, invalid_label=0, gt_target_label=0, tool_target_label=0, criticality=ErrorType.UNDEF):

        if gt_factor:
            addr     = gt_factor.addr
        else:
            addr     = tool_factor.addr

        self.adata.append(EData(addr, gt_factor, tool_factor, region, tool_reloc_type, invalid_label, gt_target_label, tool_target_label, criticality, self.sec_mgr))

    def dump(self, out_file):
        rec = ErrorRecord(self.stype, self.etype)

        for item in sorted(self.adata):
            print(rec.to_ascii(item), file=out_file)

    def length(self):
        return len(self.adata)

    def critical_errors(self):
        return len([item for item in self.adata if item.criticality not in [ErrorType.SAFE_FP, ErrorType.TP]])

    def get_errors(self):

        mylist = list()
        rec = ErrorRecord(self.stype, self.etype)
        for item in sorted(self.adata):
            mylist.append(rec.create_dict(item))
        return mylist

class RecS:
    def __init__(self, stype, sec_mgr):
        self.stype = stype
        self.fp = Record(stype, 'FP', sec_mgr)
        self.fn = Record(stype, 'FN', sec_mgr)
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

    def get_errors(self):
        if 0 == self.fp.length() + self.fn.length():
            return None

        mydict = dict()
        mydict['total_fp'] = self.fp.length()
        mydict['fatal_fp'] = self.fp.critical_errors()
        mydict['total_fn'] = self.fn.length()
        #print('Relocatable Expression Type %d [FP: %d(%d) / FN: %d]'%(self.stype, num_fp, num_critical_fp, num_fn), file = out_file)

        mydict['fp'] = self.fp.get_errors()
        mydict['fn'] = self.fn.get_errors()
        return mydict


class Report:
    def __init__(self, bin_path, prog_c):

        self.sec_mgr = SecManager(bin_path)

        self.prog_c = prog_c
        self.gt = 0

        self.bin_path = bin_path
        self.gt_path = prog_c.asm_path

        self.record = dict()
        for stype in range(1, 9):
            self.record[stype] = RecS(stype, self.sec_mgr)


    def compare(self, prog_r):
        #self.reset()
        self.tool_path = prog_r.asm_path
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
                elif data_c.r_type and data_c.r_type in ['R_X86_64_64'] and addr in prog_r.Data:
                    # when assembly refer import symbol
                    # the code will refer to .data.rel.ro section
                    # reassemblers can have different implementation
                    if data_c.value.terms[0].Address <= 0:
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

                # if the label does not has address, we consider it as constant
                # the label can be defined as constant like ".set L1234, 0x1234"
                # Thus, it is not a FP error
                if data_r.value.terms[0].Address < 0:
                    continue
                if not self.sec_mgr.is_in_data_region(addr):
                    continue
                if data_r.value.type == 7 and data_r.value.terms[0].Address == 0:
                    continue

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

        # exclude disassembly errors
        '''
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
        '''

    def compare_two_reloc_expr(self, gt_factor, tool_factor, region, addr):
        gt_reloc = None
        tool_reloc = None
        if gt_factor:
            gt_reloc = get_expr(gt_factor, region)
        if tool_factor:
            tool_reloc = get_expr(tool_factor, region)

        if gt_reloc is None and tool_reloc is None:
            return False

        gt_reloc_type = 8
        tool_reloc_type = 8

        invalid_label = 0
        result = ReportTy.UNKNOWN
        gt_target_label = 0
        tool_target_label = 0

        if gt_reloc:
            gt_reloc_type = gt_reloc.type
            if gt_reloc.terms[0].Address > 0:
                gt_target_label = gt_reloc.terms[0].Address + gt_reloc.num
            else:
                gt_target_label = gt_reloc.num

        if tool_reloc:
            tool_reloc_type = tool_reloc.type
            #tool_target_label =  tool_reloc.terms[0].Address
            tool_target_label = (tool_reloc.terms[0].Address + tool_reloc.terms[0].Num ) + tool_reloc.num

            if  tool_reloc.terms[0].Address < 0:
                if tool_reloc.terms[0].Num == 0:
                    # -1: does not exist
                    # -2: duplicated label
                    invalid_label = abs(tool_reloc.terms[0].Address)
                else:
                    invalid_label = 5 # the label refers fix address
            else:
                if ((gt_reloc and gt_target_label != tool_target_label) and
                       not tool_reloc.terms[0].get_name().endswith('@GOT') ):

                    invalid_label = 3 # label address is diffent

                elif tool_reloc.terms[0].Num:
                    invalid_label = 4 # composite .set label

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

                    else:
                        result = ReportTy.TP

            #elif tool_reloc.type == 0:
            #    result = ReportTy.FN
            else:
                result = ReportTy.FP

        elif gt_reloc:
            result = ReportTy.FN

        elif tool_reloc:
            #We allow numerical label when it is used for absolute addressing
            if invalid_label == 5 and tool_reloc_type in [1,2]:
                criticality = ErrorType.TP
                result = ReportTy.TP
            else:
                result = ReportTy.FP

        if result == ReportTy.FP:
            if gt_reloc is None:
                criticality = ErrorType.CLASSIC_FP
            elif invalid_label == 1:
                criticality = ErrorType.LABEL_UNDEF
            elif invalid_label == 2:
                criticality = ErrorType.LABEL_DUP
            elif invalid_label == 3:
                criticality = ErrorType.DIFF_ADDRS
            elif invalid_label == 5:
                criticality = ErrorType.FIXED_ADDR
                result = ReportTy.FN
            else:
                criticality = self.check_fp_criticality(gt_reloc, tool_reloc, gt_target_label, tool_target_label)

        elif result == ReportTy.FN:
            criticality = ErrorType.FN
        else: # TP
            criticality = ErrorType.TP

        #exclude label errors (undefined label or duplicated label)
        if result == ReportTy.FP and invalid_label in [1, 2]:
            return False

        self.record_result(region, result, gt_reloc_type, tool_reloc_type, gt_factor, tool_factor, invalid_label, gt_target_label, tool_target_label, criticality)
        return True

    def check_fp_criticality(self, gt_reloc, tool_reloc, gt_target_addr, tool_target_addr):

        # check types
        if gt_reloc.type == 7 and tool_reloc.type == 7:
            #print('invalid type 7')
            return ErrorType.DIFF_BASES

        if gt_reloc.type != tool_reloc.type:
            if int((gt_reloc.type-1)/2) != int((tool_reloc.type-1)/2):
                #print('different semantics')
                return ErrorType.LABEL_SEMANTICS #diff semantics


        #if label is consist with @GOT, reassessor only checks referring region
        if tool_reloc.terms[0].get_name().endswith('@GOT'):
            tool_label_sec = self.sec_mgr.get_sec_name(tool_reloc.terms[0].Address)

            tool_target_sec = self.sec_mgr.get_sec_name(tool_target_addr)

            # label & target address should be in same section.
            if tool_label_sec != tool_target_sec:
                return ErrorType.SEC_OUTSIDE

            #if tool_label_sec in ['.text', '.init', '.fini', '.plt']:
            #    return ErrorType.CODE_REGION #text section

        else:
            # check target section
            gt_label_sec = self.sec_mgr.get_sec_name(gt_reloc.terms[0].Address)
            tool_label_sec = self.sec_mgr.get_sec_name(tool_reloc.terms[0].Address)


            # if two target point to same data region, it can be considered as non-critical!!!!
            if gt_label_sec != tool_label_sec:
                return ErrorType.DIFF_SECTIONS #diff section

            gt_target_sec = self.sec_mgr.get_sec_name(gt_target_addr)

            # label & target address should be in same section.
            if gt_label_sec != gt_target_sec:
                return ErrorType.SEC_OUTSIDE

            if gt_label_sec in ['.text', '.init', '.fini', '.plt']:
                return ErrorType.CODE_REGION #text section

        # non-critical FP
        return ErrorType.SAFE_FP



    def record_result(self, region, result, gt_reloc_type, tool_reloc_type, gt_factor, tool_factor, invalid_label, gt_target_label, tool_target_label, criticality):
        if result == ReportTy.TP:
            self.record[gt_reloc_type].tp += 1
        elif result == ReportTy.FP:
            self.record[gt_reloc_type].fp.add(gt_factor, tool_factor, region, tool_reloc_type, invalid_label, gt_target_label, tool_target_label, criticality)
        elif result == ReportTy.FN:
            self.record[gt_reloc_type].fn.add(gt_factor, tool_factor, region, tool_reloc_type, invalid_label, criticality=criticality)


    def check_data_error(self, data_c, data_r, addr):

        check = False

        # skip .init_array, .fini_array
        # we cannot decide whether the symbolization errors affect program behavior
        # some missing symbol can be filled by compiler.
        sec = self.sec_mgr.get_sec_name(addr)
        if sec in ['.init_array', '.fini_array']:
            return

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
                check = self.compare_two_reloc_expr(data_c, data_r, 'Data', addr)
        else:
            check = self.compare_two_reloc_expr(data_c, data_r, 'Data', addr)

        if check:
            self.gt += 1


    def check_ins(self, ins_c, ins_r, addr):

        assert ins_c is not None and ins_r is not None

        check1 = self.compare_two_reloc_expr(ins_c, ins_r, 'Imm', addr)
        check2 = self.compare_two_reloc_expr(ins_c, ins_r, 'Disp', addr)

        if check1 or check2:
            self.gt += 1

    def save_pickle(self, file_path):
        with my_open(file_path, 'wb') as fd:
            data = ERec(self.record, self.gt, self.bin_path, self.gt_path, self.tool_path)
            pickle.dump(data, fd)

    def save_file(self, file_path, option='ascii'):
        if option not in ['ascii', 'json']:
            raise SyntaxError("Unsupported save format")

        with my_open(file_path, 'w') as fd:
            if option == 'ascii':
                self.save_ascii_file(fd)
            elif option == 'json':
                self.save_json_file(fd)

    def save_ascii_file(self, out_file):
        print('# Instrs to check:', self.ins_len, file = out_file)
        print('# Data to check:', self.data_len, file = out_file)
        for stype in range(1,9):
            self.record[stype].dump(out_file)

    def save_json_file(self, out_file):
        mydict = get_errors(self)
        print(json.dumps(mydict, indent=1), file = out_file)

def transform_json(pickle_file, json_file):
    if not os.path.exists(pickle_file):
        print('%s does not exist'%(pickle_file))
        return

    with open(pickle_file, 'rb') as fp:
        data = pickle.load(fp)
        mydict = get_errors(data)
        with open(json_file, 'w') as out_file:
            print(json.dumps(mydict, indent=1), file = out_file)


def get_errors(data):
    mydict = dict()

    mydict['bin_path'] = data.bin_path
    mydict['gt_path'] = data.gt_path
    mydict['tool_path'] = data.tool_path

    for stype in range(1, 9):
        category = 'E%d'%(stype)
        rec = data.record[stype].get_errors()
        if rec:
            mydict[category] = rec

    return mydict


import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='error report')
    parser.add_argument('pickle_file', type=str)
    parser.add_argument('json_file', type=str)
    args = parser.parse_args()

    transform_json(args.pickle_file, args.json_file)
