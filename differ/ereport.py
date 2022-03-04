import os
import json
from lib.asm_types import CmptTy

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

    def report(self, gt, tool=None, idx=-1):
        if gt:
            address = gt.Address
            src_gt      = gt.Path,    gt.Line
        else:
            address = tool.Address
            src_gt      = None

        if tool:
            src_tool    = tool.Path,  tool.Line
        else:
            src_tool    = None

        info = Info(self.stype, address, self.region, self.etype, gt,  tool, src_gt, src_tool, idx)

        self.jdata.append(info.to_json())
        self.adata.append((address, self.region, self.etype, src_gt, src_tool, idx))

    def dump(self, out_file):
        for (addr, ty, res, src_c, src_r, idx) in self.adata:
            print('T%d'%(self.stype), hex(addr), ty, res, src_c, src_r, idx, file = out_file)

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
        #self.reset()
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
                self.rec[8].fp.data.report(None, data_r)


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
        cmpt_c = ins_c.Components[idx]
        cmpt_r = ins_r.Components[idx]

        if cmpt_c.is_ms():
            self.gt += 1
            if cmpt_c.is_composite(): # Type II, IV, VI, VII
                if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
                    if not cmpt_r.is_ms():
                        self.rec[2].fn.ins.report(ins_c, ins_r, idx)
                    else:
                        if cmpt_c != cmpt_r:
                            self.rec[2].fp.ins.report(ins_c, ins_r, idx)
                        else:
                            self.rec[2].tp += 1
                elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
                    if not cmpt_r.is_ms():
                        self.rec[4].fn.ins.report(ins_c, ins_r, idx)
                    else:
                        if cmpt_c != cmpt_r:
                            self.rec[4].fp.ins.report(ins_c, ins_r, idx)
                        else:
                            self.rec[4].tp += 1
                elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
                    if not cmpt_r.is_ms():
                        self.rec[6].fn.ins.report(ins_c, ins_r, idx)
                    else:
                        if cmpt_c != cmpt_r:
                            self.rec[6].fp.ins.report(ins_c, ins_r, idx)
                        else:
                            self.rec[6].tp += 1
                elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
                    if not cmpt_r.is_ms():
                        self.rec[7].fn.ins.report(ins_c, ins_r, idx)
                    else:
                        if cmpt_c != cmpt_r:
                            self.rec[7].fp.ins.report(ins_c, ins_r, idx)
                        else:
                            self.rec[7].tp += 1
            else: # Type I, III, V
                if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
                    if not cmpt_r.is_ms():
                        self.rec[1].fn.ins.report(ins_c, ins_r, idx)
                    else:
                        if cmpt_c != cmpt_r:
                            self.rec[1].fp.ins.report(ins_c, ins_r, idx)
                        else:
                            self.rec[1].tp += 1
                elif cmpt_c.Ty == CmptTy.PCREL: # Type III
                    if not cmpt_r.is_ms():
                        self.rec[3].fn.ins.report(ins_c, ins_r, idx)
                    else:
                        if cmpt_c != cmpt_r:
                            # HSKIM: TO DO
                            if not cmpt_r.is_composite():
                                addr_c = cmpt_c.Terms[0].Address
                                addr_r = cmpt_r.Terms[0].Address
                                if (addr_r + 0x10) & 0xfffffff0 == addr_c:
                                    self.rec[3].tp += 1
                                else:
                                    self.rec[3].fp.ins.report(ins_c, ins_r, idx)
                            else:
                                self.rec[3].fp.ins.report(ins_c, ins_r, idx)
                        else:
                            self.rec[3].tp += 1
                elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
                    if not cmpt_r.is_ms():
                        self.rec[5].fn.ins.report(ins_c, ins_r, idx)
                    else:
                        if cmpt_c != cmpt_r:
                            self.rec[5].fp.ins.report(ins_c, ins_r, idx)
                        else:
                            self.rec[5].tp += 1
        elif cmpt_r.is_ms(): # FP
            self.rec[8].fp.ins.report(ins_c, ins_r, idx)

    def check_data_error(self, data_c, data_r):
        self.gt += 1
        cmpt_c = data_c.Component

        if cmpt_c.is_composite(): # Type II, IV, VI, VII
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
                if data_r is None:
                    self.rec[2].fn.data.report(data_c)
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.rec[2].fp.data.report(data_c, data_r)
                    else:
                        self.rec[2].tp += 1
            elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
                if data_r is None:
                    self.rec[4].fn.data.report(data_c)
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.rec[4].fp.data.report(data_c, data_r)
                    else:
                        self.rec[4].tp += 1
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
                if data_r is None:
                    self.rec[6].fn.data.report(data_c)
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.rec[6].fp.data.report(data_c, data_r)
                    else:
                        self.rec[6].tp += 1
            elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
                if data_r is None:
                    self.rec[7].fn.data.report(data_c)
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.rec[7].fp.data.report(data_c, data_r)
                    else:
                        self.rec[7].tp += 1
        else: # Type I, III, V
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
                if data_r is None:
                    self.rec[1].fn.data.report(data_c)
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.rec[1].fp.data.report(data_c, data_r)
                    else:
                        self.rec[1].tp += 1
            elif cmpt_c.Ty == CmptTy.PCREL: # Type III
                if data_r is None:
                    self.rec[3].fn.data.report(data_c)
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.rec[3].fp.data.report(data_c, data_r)
                    else:
                        self.rec[3].tp += 1
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
                if data_r is None:
                    self.rec[5].fn.data.report(data_c)
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.rec[4].fp.data.report(data_c, data_r)
                    else:
                        self.rec[5].tp += 1

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


