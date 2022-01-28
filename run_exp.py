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

class Report:
    def __init__(self, out_file = sys.stdout):
        self.type1 = {}
        self.type2 = {}
        self.type3 = {}
        self.type4 = {}
        self.type5 = {}
        self.type6 = {}
        self.type7 = {}
        self.type0 = {}
        self.out_file = out_file

        self.warnings = []

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

    def warning(self, addr, msg):
        self.warnings.append((addr, msg))

    # FIXME: Dump to file?
    def report(self, package, arch, compiler, pie, opt, name, tool):
        print('Testing.. [%s / %s / %s / %s / %s / %s] vs %s' % (package, arch, compiler, pie, opt, name, tool), file = self.out_file)
        if len(self.type1) > 0:
            print('Type I', file = self.out_file)
            for addr, i in self.type1:
                ty, res, src_c, src_r, idx = self.type1[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type2) > 0:
            print('Type II', file = self.out_file)
            for addr, i in self.type2:
                ty, res, src_c, src_r, idx = self.type2[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type3) > 0:
            print('Type III', file = self.out_file)
            for addr, i in self.type3:
                ty, res, src_c, src_r, idx = self.type3[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type4) > 0:
            print('Type IV', file = self.out_file)
            for addr, i in self.type4:
                ty, res, src_c, src_r, idx = self.type4[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type5) > 0:
            print('Type V', file = self.out_file)
            for addr, i in self.type5:
                ty, res, src_c, src_r, idx = self.type5[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type6) > 0:
            print('Type VI', file = self.out_file)
            for addr, i in self.type6:
                ty, res, src_c, src_r, idx = self.type6[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type7) > 0:
            print('Type VII', file = self.out_file)
            for addr, i in self.type7:
                ty, res, src_c, src_r, idx = self.type7[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

        if len(self.type0) > 0:
            print('Type VIII', file = self.out_file)
            for addr, i in self.type0:
                ty, res, src_c, src_r, idx = self.type0[addr]
                print(hex(addr), ty, res, src_c, src_r, idx, file = self.out_file)

# FIXME
def load_gt(bench_dir, match_dir, bin_path):
    prog = match_gt.main(bench_dir, bin_path, match_dir)
    return prog

# FIXME
def load_tool(tool, asm_path, bin_path):
    if tool == 'retro':
        prog, elf, cs = match_retro.gen_prog(bin_path)
        match_retro.parse_source(prog, elf, cs, asm_path)
        return prog
    elif tool == 'ramblr':
        prog, elf, cs = match_ramblr.gen_prog(bin_path)
        match_ramblr.parse_source(prog, elf, cs, asm_path)
        return prog
    elif tool == 'ddisasm':
        prog, elf, cs, main_addr = match_ddisasm.gen_prog(bin_path)
        match_ddisasm.parse_source(prog, elf, cs, asm_path, main_addr)
        return prog
    else:
        # FIXME
        return None

def get_addrs(prog_c, prog_r):
    ins_addrs_c = set(prog_c.Instrs.keys())
    ins_addrs_r = set(prog_r.Instrs.keys())

    ins_addrs = ins_addrs_c.intersection(ins_addrs_r)

    data_addrs_c = set(prog_c.Data.keys())
    data_addrs_r = set(prog_r.Data.keys())

    data_addrs = data_addrs_c.union(data_addrs_r)

    return ins_addrs, data_addrs

def report_T0_FP_Ins(report, ins_r, idx = -1):
    src_r = ins_r.Path, ins_r.Line
    report.report_type0(ins_r.Address, 'Ins', 'FP', None, src_r, idx)

def report_T1_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    report.report_type1(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T1_FN_Ins(report, ins_c, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    report.report_type1(ins_c.Address, 'Ins', 'FN', src_c, None, idx)

def report_T2_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    report.report_type2(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T2_FN_Ins(report, ins_c, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    report.report_type2(ins_c.Address, 'Ins', 'FN', src_c, None, idx)

def report_T3_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    report.report_type3(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T3_FN_Ins(report, ins_c, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    report.report_type3(ins_c.Address, 'Ins', 'FN', src_c, None, idx)

def report_T4_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    report.report_type4(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T4_FN_Ins(report, ins_c, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    report.report_type4(ins_c.Address, 'Ins', 'FN', src_c, None, idx)

def report_T5_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    report.report_type5(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T5_FN_Ins(report, ins_c, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    report.report_type5(ins_c.Address, 'Ins', 'FN', src_c, None, idx)

def report_T6_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    report.report_type6(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T6_FN_Ins(report, ins_c, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    report.report_type6(ins_c.Address, 'Ins', 'FN', src_c, None, idx)

def report_T7_FP_Ins(report, ins_c, ins_r, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    report.report_type7(ins_c.Address, 'Ins', 'FP', src_c, src_r, idx)

def report_T7_FN_Ins(report, ins_c, idx = -1):
    src_c = ins_c.Path, ins_c.Line
    report.report_type7(ins_c.Address, 'Ins', 'FN', src_c, None, idx)

def report_T0_FP_Data(report, data_r):
    src_r = data_r.Path, data_r.Line
    report.report_type0(data_r.Address, 'Data', 'FN', None, src_r)

def report_T1_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    report.report_type1(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T1_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    report.report_type1(data_c.Address, 'Data', 'FN', src_c, None)

def report_T2_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    report.report_type2(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T2_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    report.report_type2(data_c.Address, 'Data', 'FN', src_c, None)

def report_T3_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    report.report_type3(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T3_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    report.report_type3(data_c.Address, 'Data', 'FN', src_c, None)

def report_T4_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    report.report_type4(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T4_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    report.report_type4(data_c.Address, 'Data', 'FN', src_c, None)

def report_T5_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    report.report_type5(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T5_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    report.report_type5(data_c.Address, 'Data', 'FN', src_c, None)

def report_T6_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    report.report_type6(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T6_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    report.report_type6(data_c.Address, 'Data', 'FN', src_c, None)

def report_T7_FP_Data(report, data_c, data_r):
    src_c = data_c.Path, data_c.Line
    src_r = data_r.Path, data_r.Line
    report.report_type7(data_c.Address, 'Data', 'FP', src_c, src_r)

def report_T7_FN_Data(report, data_c):
    src_c = data_c.Path, data_c.Line
    report.report_type7(data_c.Address, 'Data', 'FN', src_c, None)

def check_ins_error(report, prog_c, prog_r, ins_c, ins_r, idx):
    cmpt_c = ins_c.Components[idx]
    cmpt_r = ins_r.Components[idx]

    if cmpt_c.is_ms():
        if cmpt_c.is_composite(): # Type II, IV, VI, VII
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
                if not cmpt_r.is_ms():
                    report_T2_FN_Ins(report, ins_c, idx)
                else:
                    if cmpt_c != cmpt_r:
                        report_T2_FP_Ins(report, ins_c, ins_r, idx)
            elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
                if not cmpt_r.is_ms():
                    report_T4_FN_Ins(report, ins_c, idx)
                else:
                    if cmpt_c != cmpt_r:
                        report_T4_FP_Ins(report, ins_c, ins_r, idx)
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
                if not cmpt_r.is_ms():
                    report_T6_FN_Ins(report, ins_c, idx)
                else:
                    if cmpt_c != cmpt_r:
                        report_T6_FP_Ins(report, ins_c, ins_r, idx)
            elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
                if not cmpt_r.is_ms():
                    report_T7_FN_Ins(report, ins_c, idx)
                else:
                    if cmpt_c != cmpt_r:
                        report_T7_FP_Ins(report, ins_c, ins_r, idx)
        else: # Type I, III, V
            if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
                if not cmpt_r.is_ms():
                    report_T1_FN_Ins(report, ins_c, idx)
                else:
                    if cmpt_c != cmpt_r:
                        report_T1_FP_Ins(report, ins_c, ins_r, idx)
            elif cmpt_c.Ty == CmptTy.PCREL: # Type III
                if not cmpt_r.is_ms():
                    report_T3_FN_Ins(report, ins_c, idx)
                else:
                    if cmpt_c != cmpt_r:
                        report_T3_FP_Ins(report, ins_c, ins_r, idx)
            elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
                if not cmpt_r.is_ms():
                    report_T5_FN_Ins(report, ins_c, idx)
                else:
                    if cmpt_c != cmpt_r:
                        report_T5_FP_Ins(report, ins_c, ins_r, idx)
    elif cmpt_r.is_ms(): # FP
        report_T0_FP_Ins(report, ins_r, idx)

def check_data_error(report, prog_c, prog_r, data_c, data_r):
    cmpt_c = data_c.Component

    if cmpt_c.is_composite(): # Type II, IV, VI, VII
        if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type II
            if data_r is None:
                report_T2_FN_Data(report, data_c)
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T2_FP_Data(report, data_c, data_r)
        elif cmpt_c.Ty == CmptTy.PCREL: # Type IV
            if data_r is None:
                report_T4_FN_Data(report, data_c)
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T4_FP_Data(report, data_c, data_r)
        elif cmpt_c.Ty == CmptTy.GOTOFF: # Type VI
            if data_r is None:
                report_T6_FN_Data(report, data_c)
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T6_FP_Data(report, data_c, data_r)
        elif cmpt_c.Ty == CmptTy.OBJREL: # Type VII
            if data_r is None:
                report_T7_FN_Data(report, data_c)
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T7_FP_Data(report, data_c, data_r)
    else: # Type I, III, V
        if cmpt_c.Ty == CmptTy.ABSOLUTE: # Type I
            if data_r is None:
                report_T1_FN_Data(report, data_c)
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T1_FP_Data(report, data_c, data_r)
        elif cmpt_c.Ty == CmptTy.PCREL: # Type III
            if data_r is None:
                report_T3_FN_Data(report, data_c)
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T3_FP_Data(report, data_c, data_r)
        elif cmpt_c.Ty == CmptTy.GOTOFF: # Type V
            if data_r is None:
                report_T5_FN_Data(report, data_c)
            else:
                cmpt_r = data_r.Component
                if cmpt_c != cmpt_r:
                    report_T5_FP_Data(report, data_c, data_r)

def get_cmpt_list(ins_c, ins_r):
    cmpt_c = ins_c.get_components()
    cmpt_r = ins_r.get_components()
    cmpts = list(set(cmpt_c + cmpt_r))
    cmpts.sort()
    return cmpts

def compare_ins_errors(report, prog_c, prog_r, ins_addrs):
    print('# Instrs to check:', len(ins_addrs), file = report.out_file)
    for addr in ins_addrs:
        ins_c = prog_c.Instrs[addr]
        ins_r = prog_r.Instrs[addr]

        cmpts = get_cmpt_list(ins_c, ins_r)
        for idx in cmpts:
            check_ins_error(report, prog_c, prog_r, ins_c, ins_r, idx)

def compare_data_errors(report, prog_c, prog_r, data_addrs):
    print('# Data to check:', len(data_addrs), file = report.out_file)
    for addr in data_addrs:
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

def compare(prog_c, prog_r, out_file):
    report = Report(out_file)
    ins_addrs, data_addrs = get_addrs(prog_c, prog_r)
    compare_ins_errors(report, prog_c, prog_r, ins_addrs)
    compare_data_errors(report, prog_c, prog_r, data_addrs)
    return report

TOOLS = ['retro_sym', 'ramblr', 'ddisasm']

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
    bench_dir, pickle_dir, result_dir, options = args
    package, arch, compiler, pie, opt = options
    print(package, arch, compiler, pie, opt)

    base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
    strip_dir = os.path.join(base_dir, 'stripbin')
    pickle_base_dir = os.path.join(pickle_dir, package, arch, compiler, pie, opt)

    for bin_name in os.listdir(strip_dir):
        bin_path = os.path.join(strip_dir, bin_name)
        print(bin_name)
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
                if not os.path.exists(out_file_dir):
                    os.system("mkdir -p %s" % out_file_dir)
                out_file_path = os.path.join(out_file_dir, bin_name)
                if os.path.exists(out_file_path):
                    continue
                out_file = open(out_file_path, 'w')
                print(out_file_path)
                pickle_tool_path = os.path.join(pickle_base_dir, tool, bin_name + '.p3')
                pickle_tool_f = open(pickle_tool_path, 'rb')
                prog_r = pickle.load(pickle_tool_f)
                print('Compare GT vs', tool)
                report = compare(prog_c, prog_r, out_file)
                report.report(package, arch, compiler, pie, opt, bin_name, tool)
                pickle_tool_f.close()
                out_file.close()
            pickle_gt_f.close()

def main(bench_dir, pickle_dir, result_dir):
    args = []
    for package, arch, compiler, pie, opt in gen_options():
        args.append((bench_dir, pickle_dir, result_dir, [package, arch, compiler, pie, opt]))
    p = multiprocessing.Pool(84)
    p.map(test, args)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    pickle_dir = sys.argv[2]
    result_dir = sys.argv[3]
    main(bench_dir, pickle_dir, result_dir)
