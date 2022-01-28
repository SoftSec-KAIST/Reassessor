import os, sys
from enum import Enum
from functools import reduce
from utils import *
from asm_types import *
import match_retro
import match_ramblr
import match_ddisasm
import match_gt
import pickle
import multiprocessing
import json

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
        if cls == 1 and err == 'FP':
            return 'E1FP'
        elif cls == 1 and err == 'FN':
            return 'E1FN'
        elif cls == 2 and err == 'FP':
            return 'E2FP'
        elif cls == 2 and err == 'FN':
            return 'E2FN'
        elif cls == 3 and err == 'FP':
            return 'E3FP'
        elif cls == 3 and err == 'FN':
            return 'E3FN'
        elif cls == 4 and err == 'FP':
            return 'E4FP'
        elif cls == 4 and err == 'FN':
            return 'E4FN'
        elif cls == 5 and err == 'FP':
            return 'E5FP'
        elif cls == 5 and err == 'FN':
            return 'E5FN'
        elif cls == 6 and err == 'FP':
            return 'E6FP'
        elif cls == 6 and err == 'FN':
            return 'E6FN'
        elif cls == 7 and err == 'FP':
            return 'E7FP'
        elif cls == 7 and err == 'FN':
            return 'E7FN'
        else:
            return 'E8FP'

class Report:
    def __init__(self, out_file = sys.stdout, pr_file = sys.stdout, j_file = sys.stdout):
        self.type1 = {}
        self.type2 = {}
        self.type3 = {}
        self.type4 = {}
        self.type5 = {}
        self.type6 = {}
        self.type7 = {}
        self.type0 = {}
        self.type0_7 = {}
        self.out_file = out_file
        self.pr_file = pr_file
        self.j_file = j_file

        self.e1tp = 0
        self.e1fp = 0
        self.e1fn = 0
        self.e2tp = 0
        self.e2fp = 0
        self.e2fn = 0
        self.e3tp = 0
        self.e3fp = 0
        self.e3fn = 0
        self.e4tp = 0
        self.e4fp = 0
        self.e4fn = 0
        self.e5tp = 0
        self.e5fp = 0
        self.e5fn = 0
        self.e6tp = 0
        self.e6fp = 0
        self.e6fn = 0
        self.e7tp = 0
        self.e7fp = 0
        self.e7fn = 0
        self.e8fp = 0
        self.e8fp_7 = 0

        self.gt = 0

        self.warnings = []

        self.infos = []

    def report_info(self, info):
        self.infos.append(info.to_json())

    # ty: Ins or Data
    # res: TP / FP / FN
    def report_type1(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type1[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type2(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type2[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type3(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type3[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type4(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type4[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type5(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type5[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type6(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type6[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type7(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type7[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type0(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type0[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def report_type0_7(self, addr, ty, res, src_c, src_r, idx=-1):
        self.type0_7[(addr, idx)] = (ty, res, src_c, src_r, idx)

    def warning(self, addr, msg):
        self.warnings.append((addr, msg))

    # FIXME: Dump to file?
    def report(self, package, arch, compiler, pie, opt, name, tool):
        print('Testing.. [%s / %s / %s / %s / %s / %s] vs %s' % (package, arch, compiler, pie, opt, name, tool), file = self.out_file)
        if len(self.type1) > 0:
            print('Type I', file = self.out_file)
            for addr, i in self.type1:
                ty, res, src_c, src_r, idx = self.type1[(addr, i)]
                print('T1', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type2) > 0:
            print('Type II', file = self.out_file)
            for addr, i in self.type2:
                ty, res, src_c, src_r, idx = self.type2[(addr, i)]
                print('T2', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type3) > 0:
            print('Type III', file = self.out_file)
            for addr, i in self.type3:
                ty, res, src_c, src_r, idx = self.type3[(addr, i)]
                print('T3', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type4) > 0:
            print('Type IV', file = self.out_file)
            for addr, i in self.type4:
                ty, res, src_c, src_r, idx = self.type4[(addr, i)]
                print('T4', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type5) > 0:
            print('Type V', file = self.out_file)
            for addr, i in self.type5:
                ty, res, src_c, src_r, idx = self.type5[(addr, i)]
                print('T5', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type6) > 0:
            print('Type VI', file = self.out_file)
            for addr, i in self.type6:
                ty, res, src_c, src_r, idx = self.type6[(addr, i)]
                print('T6', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type7) > 0:
            print('Type VII', file = self.out_file)
            for addr, i in self.type7:
                ty, res, src_c, src_r, idx = self.type7[(addr, i)]
                print('T7', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type0) > 0:
            print('Type VIII', file = self.out_file)
            for addr, i in self.type0:
                ty, res, src_c, src_r, idx = self.type0[(addr, i)]
                print('T8', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type0_7) > 0:
            print('Type VIII_7', file = self.out_file)
            for addr, i in self.type0_7:
                ty, res, src_c, src_r, idx = self.type0_7[(addr, i)]
                print('T9', hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        print('%d,%d,%d' % (self.e1tp, self.e1fp, self.e1fn), file = self.pr_file)
        print('%d,%d,%d' % (self.e2tp, self.e2fp, self.e2fn), file = self.pr_file)
        print('%d,%d,%d' % (self.e3tp, self.e3fp, self.e3fn), file = self.pr_file)
        print('%d,%d,%d' % (self.e4tp, self.e4fp, self.e4fn), file = self.pr_file)
        print('%d,%d,%d' % (self.e5tp, self.e5fp, self.e5fn), file = self.pr_file)
        print('%d,%d,%d' % (self.e6tp, self.e6fp, self.e6fn), file = self.pr_file)
        print('%d,%d,%d' % (self.e7tp, self.e7fp, self.e7fn), file = self.pr_file)
        print('%d' % self.e8fp, file = self.pr_file)
        print('%d' % self.gt, file = self.pr_file)
        print('%d' % self.e8fp_7, file = self.pr_file)

        print(json.dumps(self.infos, indent=2), file = self.j_file)

def get_addrs(prog_c, prog_r):
    ins_addrs_c = set(prog_c.Instrs.keys())
    ins_addrs_r = set(prog_r.Instrs.keys())

    ins_addrs = ins_addrs_c.intersection(ins_addrs_r)

    data_addrs_c = set(prog_c.Data.keys())
    data_addrs_r = set(prog_r.Data.keys())

    data_addrs = data_addrs_c.union(data_addrs_r)

    return ins_addrs, data_addrs

def report_T0_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(8, ins_r.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type0(ins_r.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T0_FP_7_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(9, ins_r.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type0(ins_r.Address, 'Ins', 'FP', src_c, src_r, idx)


def report_T1_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(1, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type1(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T1_FN_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(1, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type1(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

def report_T2_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(2, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type2(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T2_FN_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(2, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type2(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

def report_T3_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(3, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type3(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T3_FN_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(3, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type3(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

def report_T4_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(4, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type4(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T4_FN_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(4, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type4(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

def report_T5_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(5, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type5(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T5_FN_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(5, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type5(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

def report_T6_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(6, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type6(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T6_FN_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(6, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type6(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

def report_T7_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(7, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type7(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T7_FN_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    i = Info(7, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
    report.report_info(i)
    report.report_type7(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

def report_T0_FP_Data(report, data_r):
    src_r = data_r.Path, data_r.Line
    i = Info(8, data_r.Address, 'Data', 'FP', None, data_r, None, src_r, -1)
    report.report_info(i)
    report.report_type0(data_r.Address, 'Data', 'FP', None, src_r)

def report_T1_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    i = Info(1, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
    report.report_info(i)
    report.report_type1(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T1_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    i = Info(1, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
    report.report_info(i)
    report.report_type1(data_c.Address, 'Data', 'FN', src_c, None)

def report_T2_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    i = Info(2, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
    report.report_info(i)
    report.report_type2(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T2_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    i = Info(2, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
    report.report_info(i)
    report.report_type2(data_c.Address, 'Data', 'FN', src_c, None)

def report_T3_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    i = Info(3, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
    report.report_info(i)
    report.report_type3(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T3_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    i = Info(3, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
    report.report_info(i)
    report.report_type3(data_c.Address, 'Data', 'FN', src_c, None)

def report_T4_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    i = Info(4, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
    report.report_info(i)
    report.report_type4(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T4_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    i = Info(4, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
    report.report_info(i)
    report.report_type4(data_c.Address, 'Data', 'FN', src_c, None)

def report_T5_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    i = Info(5, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
    report.report_info(i)
    report.report_type5(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T5_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    i = Info(5, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
    report.report_info(i)
    report.report_type5(data_c.Address, 'Data', 'FN', src_c, None)

def report_T6_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    i = Info(6, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
    report.report_info(i)
    report.report_type6(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T6_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    i = Info(6, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
    report.report_info(i)
    report.report_type6(data_c.Address, 'Data', 'FN', src_c, None)

def report_T7_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    i = Info(7, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
    report.report_info(i)
    report.report_type7(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T7_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    i = Info(7, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
    report.report_info(i)
    report.report_type7(data_c.Address, 'Data', 'FN', src_c, None)

def check_ins_error(report, prog_c, prog_r, ins_c, ins_r, idx):
    cmpt_c = ins_c.Components[idx]
    cmpt_r = ins_r.Components[idx]

    if cmpt_c.is_ms():
        report.gt += 1
        if cmpt_c.is_composite(): # Type II, IV, VI, VII
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
                if not cmpt_r.is_ms():
                    report_T2_FN_Ins(report, ins_c, ins_r, idx)
                    report.e2fn += 1
                else:
                    if cmpt_c != cmpt_r:
                        report_T2_FP_Ins(report, ins_c, ins_r, idx)
                        report.e2fp += 1
                    else:
                        report.e2tp += 1
            elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
                if not cmpt_r.is_ms():
                    report_T4_FN_Ins(report, ins_c, ins_r, idx)
                    report.e4fn += 1
                else:
                    if cmpt_c != cmpt_r:
                        report_T4_FP_Ins(report, ins_c, ins_r, idx)
                        report.e4fp += 1
                    else:
                        report.e4tp += 1
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
                if not cmpt_r.is_ms():
                    report_T6_FN_Ins(report, ins_c, ins_r, idx)
                    report.e6fn += 1
                else:
                    if cmpt_c != cmpt_r:
                        report_T6_FP_Ins(report, ins_c, ins_r, idx)
                        report.e6fp += 1
                    else:
                        report.e6tp += 1
            elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
                if not cmpt_r.is_ms():
                    report_T7_FN_Ins(report, ins_c, ins_r, idx)
                    report.e7fn += 1
                else:
                    if cmpt_c != cmpt_r:
                        report_T7_FP_Ins(report, ins_c, ins_r, idx)
                        report.e7fp += 1
                    else:
                        report.e7tp += 1
        else: # Type I, III, V
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
                if not cmpt_r.is_ms():
                    report_T1_FN_Ins(report, ins_c, ins_r, idx)
                    report.e1fn += 1
                else:
                    if cmpt_c != cmpt_r:
                        report_T1_FP_Ins(report, ins_c, ins_r, idx)
                        report.e1fp += 1
                    else:
                        report.e1tp += 1
            elif cmpt_c.Ty == CmptTy.PCREL: # Type III
                if not cmpt_r.is_ms():
                    report_T3_FN_Ins(report, ins_c, ins_r, idx)
                    report.e3fn += 1
                else:
                    if cmpt_c != cmpt_r:
                        # HSKIM: TO DO
                        if not cmpt_r.is_composite():
                            addr_c = cmpt_c.Terms[0].Address
                            addr_r = cmpt_r.Terms[0].Address
                            if (addr_r + 0x10) & 0xfffffff0 == addr_c:
                                report.e3tp += 1
                            else:
                                report_T3_FP_Ins(report, ins_c, ins_r, idx)
                                report.e3fp += 1
                        else:
                            report_T3_FP_Ins(report, ins_c, ins_r, idx)
                            report.e3fp += 1
                    else:
                        report.e3tp += 1
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
                if not cmpt_r.is_ms():
                    report_T5_FN_Ins(report, ins_c, ins_r, idx)
                    report.e5fn += 1
                else:
                    if cmpt_c != cmpt_r:
                        report_T5_FP_Ins(report, ins_c, ins_r, idx)
                        report.e5fp += 1
                    else:
                        report.e5tp += 1
    elif cmpt_r.is_ms(): # FP
        report_T0_FP_Ins(report, ins_c, ins_r, idx)
        report.e8fp += 1
        if cmpt_r.Ty == CmptTy.OBJREL: # Type VII
            report.e8fp_7 += 1
            report_T0_FP_7_Ins(report, ins_c, ins_r, idx)

def check_data_error(report, prog_c, prog_r, data_c, data_r):
    report.gt += 1
    cmpt_c = data_c.Component

    if cmpt_c.is_composite(): # Type II, IV, VI, VII
        if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
            if data_r is None:
                report_T2_FN_Data(report, data_c)
                report.e2fn += 1
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T2_FP_Data(report, data_c, data_r)
                    report.e2fp += 1
                else:
                    report.e2tp += 1
        elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
            if data_r is None:
                report_T4_FN_Data(report, data_c)
                report.e4fn += 1
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T4_FP_Data(report, data_c, data_r)
                    report.e4fp += 1
                else:
                    report.e4tp += 1
        elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
            if data_r is None:
                report_T6_FN_Data(report, data_c)
                report.e6fn += 1
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T6_FP_Data(report, data_c, data_r)
                    report.e6fp += 1
                else:
                    report.e6tp += 1
        elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
            if data_r is None:
                report_T7_FN_Data(report, data_c)
                report.e7fn += 1
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T7_FP_Data(report, data_c, data_r)
                    report.e7fp += 1
                else:
                    report.e7tp += 1
    else: # Type I, III, V
        if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
            if data_r is None:
                report_T1_FN_Data(report, data_c)
                report.e1fn += 1
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T1_FP_Data(report, data_c, data_r)
                    report.e1fp += 1
                else:
                    report.e1tp += 1
        elif cmpt_c.Ty == CmptTy.PCREL: # Type III
            if data_r is None:
                report_T3_FN_Data(report, data_c)
                report.e3fn += 1
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T3_FP_Data(report, data_c, data_r)
                    report.e3fp += 1
                else:
                    report.e3tp += 1
        elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
            if data_r is None:
                report_T5_FN_Data(report, data_c)
                report.e5fn += 1
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T5_FP_Data(report, data_c, data_r)
                    report.e5fp += 1
                else:
                    report.e5tp += 1

def get_cmpt_list(ins_c, ins_r):
    cmpt_c = ins_c.get_components()
    cmpt_r = ins_r.get_components()
    cmpts = list(set(cmpt_c + cmpt_r))
    cmpts.sort()
    return cmpts

def compare_ins_errors(report, prog_c, prog_r, ins_addrs):
    print('# Instrs to check:', len(ins_addrs), file = report.out_file)
    for addr in ins_addrs:
        #if addr in [0x80491f6]:
        #    import pdb
        #    pdb.set_trace()
        ins_c = prog_c.Instrs[addr]
        ins_r = prog_r.Instrs[addr]

        cmpts = get_cmpt_list(ins_c, ins_r)
        for idx in cmpts:
            check_ins_error(report, prog_c, prog_r, ins_c, ins_r, idx)

def compare_data_errors(report, prog_c, prog_r, data_addrs):
    print('# Data to check:', len(data_addrs), file = report.out_file)
    for addr in data_addrs:
        #if addr in [0x40c7b0]:
        #    import pdb
        #    pdb.set_trace()
        if addr in prog_c.Data and addr in prog_r.Data: # TP or FP
            data_c = prog_c.Data[addr]
            data_r = prog_r.Data[addr]
            check_data_error(report, prog_c, prog_r, data_c, data_r)
        elif addr in prog_c.Data: # FN
            data_c = prog_c.Data[addr]
            check_data_error(report, prog_c, prog_r, data_c, None)
        elif addr in prog_r.Data: # FP
            data_r = prog_r.Data[addr]
            report_T0_FP_Data(report, data_r)
            report.e8fp += 1

def compare(prog_c, prog_r, out_file, pr_file, json_file):
    report = Report(out_file, pr_file, json_file)
    ins_addrs, data_addrs = get_addrs(prog_c, prog_r)
    compare_ins_errors(report, prog_c, prog_r, ins_addrs)
    compare_data_errors(report, prog_c, prog_r, data_addrs)
    return report

TOOLS = ['retro_sym', 'ramblr', 'ddisasm']
#TOOLS = ['ddisasm']

def get_available_tools(pickle_dir, bin_name):
    tools = []
    for tool in TOOLS:
        tool_path = os.path.join(pickle_dir, tool, bin_name + '.p3')
        print(tool_path)
        if not os.path.exists(tool_path):
            print(tool, 'Not Exists')
            continue
        tools.append(tool)
    return tools

def test(args): # TODO: give appropriate parameters
    bench_dir, pickle_dir, result_dir, pr_dir, json_dir, options = args
    package, arch, compiler, pie, opt = options
    print(package, arch, compiler, pie, opt)

    base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
    strip_dir = os.path.join(base_dir, 'stripbin')
    pickle_base_dir = os.path.join(pickle_dir, package, arch, compiler, pie, opt)

    for bin_name in os.listdir(strip_dir):
        bin_path = os.path.join(strip_dir, bin_name)
        #print(bin_name)
        available_tools = get_available_tools(pickle_base_dir, bin_name)
        if len(available_tools) > 0:
            # Load GT
            pickle_gt_path = os.path.join(pickle_base_dir, 'gt', bin_name + '.p3')
            if not os.path.exists(pickle_gt_path):
                print('No gt ' + pickle_gt_path)
                continue

            pickle_gt_f = open(pickle_gt_path, 'rb')
            prog_c = pickle.load(pickle_gt_f)

            for tool in available_tools:
                out_file_dir = os.path.join(result_dir, package, arch, compiler, pie, opt, tool)
                pr_file_dir = os.path.join(pr_dir, package, arch, compiler, pie, opt, tool)
                json_file_dir = os.path.join(json_dir, package, arch, compiler, pie, opt, tool)
                if not os.path.exists(out_file_dir):
                    os.system("mkdir -p %s" % out_file_dir)
                if not os.path.exists(pr_file_dir):
                    os.system("mkdir -p %s" % pr_file_dir)
                if not os.path.exists(json_file_dir):
                    os.system("mkdir -p %s" % json_file_dir)
                out_file_path = os.path.join(out_file_dir, bin_name)
                pr_file_path = os.path.join(pr_file_dir, bin_name)
                json_file_path = os.path.join(json_file_dir, bin_name)
                if os.path.exists(out_file_path):
                    continue
                out_file = open(out_file_path, 'w')
                pr_file = open(pr_file_path, 'w')
                json_file = open(json_file_path, 'w')
                print(out_file_path)
                print(pr_file_path)
                print(json_file_path)
                pickle_tool_path = os.path.join(pickle_base_dir, tool, bin_name + '.p3')
                pickle_tool_f = open(pickle_tool_path, 'rb')
                prog_r = pickle.load(pickle_tool_f)
                print('Compare GT vs', tool)
                report = compare(prog_c, prog_r, out_file, pr_file, json_file)
                report.report(package, arch, compiler, pie, opt, bin_name, tool)
                pickle_tool_f.close()
                out_file.close()
                pr_file.close()
                json_file.close()
            pickle_gt_f.close()

def main(bench_dir, pickle_dir, result_dir, pr_dir, json_dir):
    args = []
    for package, arch, compiler, pie, opt in gen_options():
        args.append((bench_dir, pickle_dir, result_dir, pr_dir, json_dir, [package, arch, compiler, pie, opt]))
    p = multiprocessing.Pool(84)
    p.map(test, args)
    #test(args[0])
    #test((bench_dir, pickle_dir, result_dir, pr_dir, json_dir, [package, 'x86', 'clang', 'nopie', 'ofast-gold']))

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    pickle_dir = sys.argv[2]
    #pickle_dir = '/home/bbbig/tmp/pickles4'
    result_dir = sys.argv[3]
    #result_dir = '/home/soomink/res5'
    pr_dir = sys.argv[4]
    #pr_dir = '/home/soomink/pr5'
    json_dir = sys.argv[5]
    #json_dir = '/home/soomink/json5'
    main(bench_dir, pickle_dir, result_dir, pr_dir, json_dir)
