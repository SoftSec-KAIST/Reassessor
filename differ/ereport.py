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
    def __init__(self, prog_c):
        self.prog_c = prog_c
        self.reset()

    def reset(self):
        self.type1 = {}
        self.type2 = {}
        self.type3 = {}
        self.type4 = {}
        self.type5 = {}
        self.type6 = {}
        self.type7 = {}
        self.type0 = {}
        self.type0_7 = {}

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

        self.ins_len = 0
        self.data_len = 0

    def compare(self, prog_r):
        self.reset()
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
                self.report_T0_FP_Data(data_r)
                self.e8fp += 1


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
        if len(self.type1) > 0:
            print('Type I', file = out_file)
            for addr, i in self.type1:
                ty, res, src_c, src_r, idx = self.type1[(addr, i)]
                print('T1', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type2) > 0:
            print('Type II', file = out_file)
            for addr, i in self.type2:
                ty, res, src_c, src_r, idx = self.type2[(addr, i)]
                print('T2', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type3) > 0:
            print('Type III', file = out_file)
            for addr, i in self.type3:
                ty, res, src_c, src_r, idx = self.type3[(addr, i)]
                print('T3', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type4) > 0:
            print('Type IV', file = out_file)
            for addr, i in self.type4:
                ty, res, src_c, src_r, idx = self.type4[(addr, i)]
                print('T4', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type5) > 0:
            print('Type V', file = out_file)
            for addr, i in self.type5:
                ty, res, src_c, src_r, idx = self.type5[(addr, i)]
                print('T5', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type6) > 0:
            print('Type VI', file = out_file)
            for addr, i in self.type6:
                ty, res, src_c, src_r, idx = self.type6[(addr, i)]
                print('T6', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type7) > 0:
            print('Type VII', file = out_file)
            for addr, i in self.type7:
                ty, res, src_c, src_r, idx = self.type7[(addr, i)]
                print('T7', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type0) > 0:
            print('Type VIII', file = out_file)
            for addr, i in self.type0:
                ty, res, src_c, src_r, idx = self.type0[(addr, i)]
                print('T8', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

        if len(self.type0_7) > 0:
            print('Type VIII_7', file = out_file)
            for addr, i in self.type0_7:
                ty, res, src_c, src_r, idx = self.type0_7[(addr, i)]
                print('T9', hex(addr), ty, res, src_c, src_r, idx, file = out_file)

    def save_default_file(self, pr_file):
        print('%d,%d,%d' % (self.e1tp, self.e1fp, self.e1fn), file = pr_file)
        print('%d,%d,%d' % (self.e2tp, self.e2fp, self.e2fn), file = pr_file)
        print('%d,%d,%d' % (self.e3tp, self.e3fp, self.e3fn), file = pr_file)
        print('%d,%d,%d' % (self.e4tp, self.e4fp, self.e4fn), file = pr_file)
        print('%d,%d,%d' % (self.e5tp, self.e5fp, self.e5fn), file = pr_file)
        print('%d,%d,%d' % (self.e6tp, self.e6fp, self.e6fn), file = pr_file)
        print('%d,%d,%d' % (self.e7tp, self.e7fp, self.e7fn), file = pr_file)
        print('%d' % self.e8fp, file = pr_file)
        print('%d' % self.gt, file = pr_file)
        print('%d' % self.e8fp_7, file = pr_file)

    def save_json_file(self, j_file):
        print(json.dumps(self.infos, indent=2), file = j_file)

    def report_T0_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(8, ins_r.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type0(ins_r.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T0_FP_7_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(9, ins_r.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type0(ins_r.Address, 'Ins', 'FP', src_c, src_r, idx)


    def report_T1_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(1, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type1(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T1_FN_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(1, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type1(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

    def report_T2_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(2, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type2(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T2_FN_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(2, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type2(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

    def report_T3_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(3, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type3(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T3_FN_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(3, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type3(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

    def report_T4_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(4, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type4(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T4_FN_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(4, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type4(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

    def report_T5_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(5, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type5(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T5_FN_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(5, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type5(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

    def report_T6_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(6, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type6(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T6_FN_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(6, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type6(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

    def report_T7_FP_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(7, ins_c.Address, 'Ins', 'FP', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type7(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

    def report_T7_FN_Ins(self, ins_c, ins_r, idx = -1):
        src_c = ins_c.Path, ins_c.Line
        src_r = ins_r.Path, ins_r.Line
        i = Info(7, ins_c.Address, 'Ins', 'FN', ins_c, ins_r, src_c, src_r, idx)
        self.report_info(i)
        self.report_type7(ins_c.Address, 'Ins', 'FN', src_c, src_r, idx)

    def report_T0_FP_Data(self, data_r):
        src_r = data_r.Path, data_r.Line
        i = Info(8, data_r.Address, 'Data', 'FP', None, data_r, None, src_r, -1)
        self.report_info(i)
        self.report_type0(data_r.Address, 'Data', 'FP', None, src_r)

    def report_T1_FP_Data(self, data_c, data_r):
        src_c = data_c.Path, data_c.Line
        src_r = data_r.Path, data_r.Line
        i = Info(1, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
        self.report_info(i)
        self.report_type1(data_c.Address, 'Data', 'FP', src_c, src_r)

    def report_T1_FN_Data(self, data_c):
        src_c = data_c.Path, data_c.Line
        i = Info(1, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
        self.report_info(i)
        self.report_type1(data_c.Address, 'Data', 'FN', src_c, None)

    def report_T2_FP_Data(self, data_c, data_r):
        src_c = data_c.Path, data_c.Line
        src_r = data_r.Path, data_r.Line
        i = Info(2, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
        self.report_info(i)
        self.report_type2(data_c.Address, 'Data', 'FP', src_c, src_r)

    def report_T2_FN_Data(self, data_c):
        src_c = data_c.Path, data_c.Line
        i = Info(2, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
        self.report_info(i)
        self.report_type2(data_c.Address, 'Data', 'FN', src_c, None)

    def report_T3_FP_Data(self, data_c, data_r):
        src_c = data_c.Path, data_c.Line
        src_r = data_r.Path, data_r.Line
        i = Info(3, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
        self.report_info(i)
        self.report_type3(data_c.Address, 'Data', 'FP', src_c, src_r)

    def report_T3_FN_Data(self, data_c):
        src_c = data_c.Path, data_c.Line
        i = Info(3, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
        self.report_info(i)
        self.report_type3(data_c.Address, 'Data', 'FN', src_c, None)

    def report_T4_FP_Data(self, data_c, data_r):
        src_c = data_c.Path, data_c.Line
        src_r = data_r.Path, data_r.Line
        i = Info(4, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
        self.report_info(i)
        self.report_type4(data_c.Address, 'Data', 'FP', src_c, src_r)

    def report_T4_FN_Data(self, data_c):
        src_c = data_c.Path, data_c.Line
        i = Info(4, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
        self.report_info(i)
        self.report_type4(data_c.Address, 'Data', 'FN', src_c, None)

    def report_T5_FP_Data(self, data_c, data_r):
        src_c = data_c.Path, data_c.Line
        src_r = data_r.Path, data_r.Line
        i = Info(5, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
        self.report_info(i)
        self.report_type5(data_c.Address, 'Data', 'FP', src_c, src_r)

    def report_T5_FN_Data(self, data_c):
        src_c = data_c.Path, data_c.Line
        i = Info(5, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
        self.report_info(i)
        self.report_type5(data_c.Address, 'Data', 'FN', src_c, None)

    def report_T6_FP_Data(self, data_c, data_r):
        src_c = data_c.Path, data_c.Line
        src_r = data_r.Path, data_r.Line
        i = Info(6, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
        self.report_info(i)
        self.report_type6(data_c.Address, 'Data', 'FP', src_c, src_r)

    def report_T6_FN_Data(self, data_c):
        src_c = data_c.Path, data_c.Line
        i = Info(6, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
        self.report_info(i)
        self.report_type6(data_c.Address, 'Data', 'FN', src_c, None)

    def report_T7_FP_Data(self, data_c, data_r):
        src_c = data_c.Path, data_c.Line
        src_r = data_r.Path, data_r.Line
        i = Info(7, data_c.Address, 'Data', 'FP', data_c, data_r, src_c, src_r, -1)
        self.report_info(i)
        self.report_type7(data_c.Address, 'Data', 'FP', src_c, src_r)

    def report_T7_FN_Data(self, data_c):
        src_c = data_c.Path, data_c.Line
        i = Info(7, data_c.Address, 'Data', 'FN', data_c, None, src_c, None, -1)
        self.report_info(i)
        self.report_type7(data_c.Address, 'Data', 'FN', src_c, None)

    def check_ins_error(self, ins_c, ins_r, idx):
        cmpt_c = ins_c.Components[idx]
        cmpt_r = ins_r.Components[idx]

        if cmpt_c.is_ms():
            self.gt += 1
            if cmpt_c.is_composite(): # Type II, IV, VI, VII
                if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
                    if not cmpt_r.is_ms():
                        self.report_T2_FN_Ins(ins_c, ins_r, idx)
                        self.e2fn += 1
                    else:
                        if cmpt_c != cmpt_r:
                            self.report_T2_FP_Ins(ins_c, ins_r, idx)
                            self.e2fp += 1
                        else:
                            self.e2tp += 1
                elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
                    if not cmpt_r.is_ms():
                        self.report_T4_FN_Ins(ins_c, ins_r, idx)
                        self.e4fn += 1
                    else:
                        if cmpt_c != cmpt_r:
                            self.report_T4_FP_Ins(ins_c, ins_r, idx)
                            self.e4fp += 1
                        else:
                            self.e4tp += 1
                elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
                    if not cmpt_r.is_ms():
                        self.report_T6_FN_Ins(ins_c, ins_r, idx)
                        self.e6fn += 1
                    else:
                        if cmpt_c != cmpt_r:
                            self.report_T6_FP_Ins(ins_c, ins_r, idx)
                            self.e6fp += 1
                        else:
                            report.e6tp += 1
                elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
                    if not cmpt_r.is_ms():
                        self.report_T7_FN_Ins(ins_c, ins_r, idx)
                        self.e7fn += 1
                    else:
                        if cmpt_c != cmpt_r:
                            self.report_T7_FP_Ins(ins_c, ins_r, idx)
                            self.e7fp += 1
                        else:
                            self.e7tp += 1
            else: # Type I, III, V
                if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
                    if not cmpt_r.is_ms():
                        self.report_T1_FN_Ins(ins_c, ins_r, idx)
                        self.e1fn += 1
                    else:
                        if cmpt_c != cmpt_r:
                            self.report_T1_FP_Ins(ins_c, ins_r, idx)
                            self.e1fp += 1
                        else:
                            self.e1tp += 1
                elif cmpt_c.Ty == CmptTy.PCREL: # Type III
                    if not cmpt_r.is_ms():
                        self.report_T3_FN_Ins(ins_c, ins_r, idx)
                        self.e3fn += 1
                    else:
                        if cmpt_c != cmpt_r:
                            # HSKIM: TO DO
                            if not cmpt_r.is_composite():
                                addr_c = cmpt_c.Terms[0].Address
                                addr_r = cmpt_r.Terms[0].Address
                                if (addr_r + 0x10) & 0xfffffff0 == addr_c:
                                    self.e3tp += 1
                                else:
                                    self.report_T3_FP_Ins(ins_c, ins_r, idx)
                                    self.e3fp += 1
                            else:
                                self.report_T3_FP_Ins(ins_c, ins_r, idx)
                                self.e3fp += 1
                        else:
                            self.e3tp += 1
                elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
                    if not cmpt_r.is_ms():
                        self.report_T5_FN_Ins(ins_c, ins_r, idx)
                        self.e5fn += 1
                    else:
                        if cmpt_c != cmpt_r:
                            self.report_T5_FP_Ins(ins_c, ins_r, idx)
                            self.e5fp += 1
                        else:
                            self.e5tp += 1
        elif cmpt_r.is_ms(): # FP
            self.report_T0_FP_Ins(ins_c, ins_r, idx)
            self.e8fp += 1
            if cmpt_r.Ty == CmptTy.OBJREL: # Type VII
                self.e8fp_7 += 1
                self.report_T0_FP_7_Ins(ins_c, ins_r, idx)

    def check_data_error(self, data_c, data_r):
        self.gt += 1
        cmpt_c = data_c.Component

        if cmpt_c.is_composite(): # Type II, IV, VI, VII
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
                if data_r is None:
                    self.report_T2_FN_Data(data_c)
                    self.e2fn += 1
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.report_T2_FP_Data(data_c, data_r)
                        self.e2fp += 1
                    else:
                        self.e2tp += 1
            elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
                if data_r is None:
                    self.report_T4_FN_Data(data_c)
                    self.e4fn += 1
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.report_T4_FP_Data(data_c, data_r)
                        self.e4fp += 1
                    else:
                        self.e4tp += 1
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
                if data_r is None:
                    self.report_T6_FN_Data(data_c)
                    self.e6fn += 1
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.report_T6_FP_Data(data_c, data_r)
                        sefl.e6fp += 1
                    else:
                        self.e6tp += 1
            elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
                if data_r is None:
                    self.report_T7_FN_Data(data_c)
                    self.e7fn += 1
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.report_T7_FP_Data(data_c, data_r)
                        self.e7fp += 1
                    else:
                        self.e7tp += 1
        else: # Type I, III, V
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
                if data_r is None:
                    self.report_T1_FN_Data(data_c)
                    self.e1fn += 1
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.report_T1_FP_Data(data_c, data_r)
                        self.e1fp += 1
                    else:
                        self.e1tp += 1
            elif cmpt_c.Ty == CmptTy.PCREL: # Type III
                if data_r is None:
                    self.report_T3_FN_Data(data_c)
                    self.e3fn += 1
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.report_T3_FP_Data(data_c, data_r)
                        self.e3fp += 1
                    else:
                        self.e3tp += 1
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
                if data_r is None:
                    self.report_T5_FN_Data(data_c)
                    self.e5fn += 1
                else:
                    cmpt_r = data_r.Component
                    if cmpt_c != cmpt_r:
                        self.report_T5_FP_Data(data_c, data_r)
                        self.e5fp += 1
                    else:
                        self.e5tp += 1

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


