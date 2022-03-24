from collections import namedtuple
import pickle
import os
import json
from lib.asm_types import CmptTy

ERec = namedtuple('ERec', ['record', 'gt'])

class Info:
    def __init__(self, cls, addr, ty, res, obj_c, obj_r, src_c, src_r, idx):
        if src_c is None:
            src_c = []
        else:
            src_c = list(src_c)
        if src_r is None:
            src_r = []
        else:
            src_r = list(src_r)
        self.j = {
                'Error': self.get_err_type(cls, res),
                'Addr': addr,
                'Idx': idx,
                'Class': ty,
                'Expr_C': self.get_expr(ty, obj_c, idx, 'C', res),
                'Expr_R': self.get_expr(ty, obj_r, idx, 'R', res),
                'Src_C': src_c,
                'Src_R': src_r
                }

    def to_json(self):
        return self.j

    def get_expr(self, ty, obj, idx, tool, res):
        if ty == 'Ins' and tool == 'C' and res == 'FP':
            cmpt = obj.Components[idx]
            return cmpt.to_json()
        elif ty == 'Ins' and tool == 'C' and res == 'FN':
            cmpt = obj.Components[idx]
            return cmpt.to_json()
        elif ty == 'Ins' and tool == 'R' and res == 'FP':
            cmpt = obj.Components[idx]
            return cmpt.to_json()
        elif ty == 'Ins' and tool == 'R' and res == 'FN':
            cmpt = obj.Components[idx]
            return cmpt.to_json()
        elif ty == 'Data' and tool == 'C' and res == 'FP':
            if obj is None:
                return {}
            else:
                cmpt = obj.Component
                return cmpt.to_json()
        elif ty == 'Data' and tool == 'C' and res == 'FN':
            cmpt = obj.Component
            return cmpt.to_json()
        elif ty == 'Data' and tool == 'R' and res == 'FP':
            if obj is None:
                return {}
            else:
                cmpt = obj.Component
                return cmpt.to_json()
        elif ty == 'Data' and tool == 'R' and res == 'FN':
            return {}

    def get_err_type(self, cls, err):
        if 1 <= cls and cls <= 7:
            return 'E%d%s'%(cls, err)
        else:
            return 'E8FP'

class Record:
    def __init__(self, stype, etype, region):
        self.stype = stype      #1-8
        self.etype = etype      #FP/FN
        self.region = region    #Ins/Data

        self.jdata = []
        self.adata = []

    def add(self, gt, tool=None, idx=-1):
        if gt:
            address     = gt.Address
            src_gt      = gt.Path,    gt.Line
            gt_asm      = gt.asm
        else:
            address     = tool.Address
            src_gt      = None
            gt_asm      = None

        if tool:
            src_tool    = tool.Path,  tool.Line
            tool_asm    = tool.asm
        else:
            src_tool    = None
            tool_asm    = None

        info = Info(self.stype, address, self.region, self.etype, gt,  tool, src_gt, src_tool, idx)

        self.jdata.append(info.to_json())
        #self.adata.append((address, self.region, self.etype, src_gt, src_tool, idx))
        self.adata.append((address, self.region, self.etype, src_gt, src_tool, idx, gt_asm, tool_asm))

    def dump(self, out_file):
        for (addr, ty, res, src_c, src_r, idx, gt_asm, tool_asm) in self.adata:
            print('T%d'%(self.stype), hex(addr), ty, res, src_c, src_r, idx, file = out_file)
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
                self.rec[8].fp.data.add(None, data_r)


    def compare_ins_errors(self, prog_r):

        ins_addrs_c = set(self.prog_c.Instrs.keys())
        ins_addrs_r = set(prog_r.Instrs.keys())
        ins_addrs = ins_addrs_c.intersection(ins_addrs_r)

        self.ins_len = len(ins_addrs)

        for addr in ins_addrs:

            ins_c = self.prog_c.Instrs[addr]
            ins_r = prog_r.Instrs[addr]

            cmpts = get_cmpt_list(ins_c, ins_r)
            for idx in cmpts:
                self.check_ins_error(ins_c, ins_r, idx)

    def pickle(self, file_path):
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


    def check_ins_error(self, ins_c, ins_r, idx):
        self.gt += 1

        if idx >= len(ins_c.Components):
            import pdb
            pdb.set_trace()
        cmpt_c = ins_c.Components[idx]
        cmpt_r = ins_r.Components[idx]

        c_type = cmpt_c.get_type()
        r_type = cmpt_r.get_type()
        if c_type == r_type:
            self.rec[c_type].tp += 1
        elif r_type == 8:
            self.rec[c_type].fn.ins.add(ins_c, ins_r, idx)
        else:
            self.rec[c_type].fp.ins.add(ins_c, ins_r, idx)


    def check_data_error(self, data_c, data_r):
        self.gt += 1

        cmpt_c = data_c.Component
        c_type = cmpt_c.get_type()
        if data_r is None:
            # this is reassembler design choice
            # ddisasm preserve .got section
            # retrowrite delete .got section
            # Thus, we do not check this case
            if data_c.asm in ['R_X86_64_GLOB_DAT']:
                pass
            elif data_c.asm in ['R_X86_64_JUMP_SLOT']:
                pass
            else:
                self.rec[c_type].fn.data.add(data_c)
        else:
            cmpt_r = data_r.Component
            r_type = cmpt_r.get_type()

            if c_type == r_type:
                self.rec[c_type].tp += 1
            else:
                self.rec[c_type].fp.data.add(data_c, data_r)

def get_cmpt_list(ins_c, ins_r):
    cmpt_c = ins_c.get_components()
    cmpt_r = ins_r.get_components()
    cmpts = list(set(cmpt_c + cmpt_r))
    cmpts.sort()
    return cmpts


def my_open(file_path, option='w'):
    if 'w' in option:
        dir_name = os.path.dirname(file_path)
        if not os.path.exists(dir_name):
            os.system("mkdir -p %s" % dir_name)
    fd = open(file_path, option)
    return fd


