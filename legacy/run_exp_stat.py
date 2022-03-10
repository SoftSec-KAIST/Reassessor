import os, sys
from enum import Enum
from functools import reduce
from asm_types import *
import match_retro
import match_ramblr
import match_ddisasm
import match_gt
import traceback
from utils import *

def open_file(path):
    if os.path.exists(path):
        return open(path, 'a')
    else:
        return open(path, 'w')

def write_file(path, data):
    if os.path.exists(path):
        opt = 'a'
    else:
        opt = 'w'
    with open(path, opt) as f:
        f.write(data)

class Report:
    def __init__(self):
        self.tot_instr = 0
        self.tp_instr = 0

        self.type1 = {}
        self.type2 = {}
        self.type3 = {}
        self.type4 = {}
        self.type5 = {}
        self.type6 = {}

        self.warnings = []

    def record_disasm_result(self, total, tp):
        self.tot_instr = total
        self.tp_instr = tp

    # res: TP / FP / FN
    # oty: On
    def report_type1(self, addr, idx, res, oty, src_c, src_r):
        self.type1[addr] = (idx, res, oty, src_c, src_r)

    def report_type2(self, addr, idx, res, oty, src_c, src_r):
        self.type2[addr] = (idx, res, oty, src_c, src_r)

    def report_type3(self, addr, res, oty, src_c, src_r):
        self.type3[addr] = (res, oty, src_c, src_r)

    def report_type4(self, addr, res, oty, src_c, src_r):
        self.type4[addr] = (res, oty, src_c, src_r)

    def report_type5(self, addr, idx, res, oty, src_c, src_r):
        self.type5[addr] = (idx, res, oty, src_c, src_r)

    def report_type6(self, addr, idx, res, oty, src_c, src_r):
        self.type6[addr] = (idx, res, oty, src_c, src_r)

    def warning(self, addr, msg):
        self.warnings.append((addr, msg))

    def report(self):
        if len(self.type1) > 0:
            print('Type I')
            for addr in self.type1:
                idx, res, oty, src_c, src_r = self.type1[addr]
                print(hex(addr), idx, res, oty, src_c, src_r)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c) as f:
                    lines = f.readlines()
                    print(lines[line_c].strip())
                with open(path_r) as f:
                    lines = f.readlines()
                    print(lines[line_r].strip())
                input()
        '''
        if len(self.type2) > 0:
            print('Type II')
            for addr in self.type2:
                idx, res, oty, src_c, src_r = self.type2[addr]
                print(hex(addr), idx, res, oty, src_c, src_r)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c) as f:
                    lines = f.readlines()
                    print(lines[line_c].strip())
                with open(path_r) as f:
                    lines = f.readlines()
                    print(lines[line_r].strip())
                input()
        '''
        if len(self.type3) > 0:
            print('Type III')
            for addr in self.type3:
                res, oty, src_c, src_r = self.type3[addr]
                print(hex(addr), res, oty, src_c, src_r)
                if src_c:
                    path_c, line_c = src_c
                    with open(path_c) as f:
                        lines = f.readlines()
                        print(lines[line_c].strip())
                else:
                    print(None)
                if src_r:
                    path_r, line_r = src_r
                    with open(path_r) as f:
                        lines = f.readlines()
                        print(lines[line_r].strip())
                else:
                    print(None)
                input()
        if len(self.type4) > 0:
            print('Type IV')
            for addr in self.type4:
                res, oty, src_c, src_r = self.type4[addr]
                print(hex(addr), res, oty, src_c, src_r)
                if src_c:
                    path_c, line_c = src_c
                    with open(path_c) as f:
                        lines = f.readlines()
                        print(lines[line_c].strip())
                else:
                    print(None)
                if src_r:
                    path_r, line_r = src_r
                    with open(path_r) as f:
                        lines = f.readlines()
                        print(lines[line_r].strip())
                else:
                    print(None)
                input()
        if len(self.type5) > 0:
            print('Type V')
            for addr in self.type5:
                idx, res, oty, src_c, src_r = self.type5[addr]
                print(hex(addr), idx, res, oty, src_c, src_r)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c) as f:
                    lines = f.readlines()
                    print(lines[line_c].strip())
                with open(path_r) as f:
                    lines = f.readlines()
                    print(lines[line_r].strip())
                input()
        '''
        if len(self.type6) > 0:
            print('Type VI')
            for addr in self.type6:
                idx, res, oty, src_c, src_r = self.type6[addr]
                print(hex(addr), idx, res, oty, src_c, src_r)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c) as f:
                    lines = f.readlines()
                    print(lines[line_c].strip())
                with open(path_r) as f:
                    lines = f.readlines()
                    print(lines[line_r].strip())
                input()
        '''

    def save_report_data(self, fp):
        if len(self.type1) > 0:
            print('Type I', file = fp)
            for addr in self.type1:
                idx, res, oty, src_c, src_r = self.type1[addr]
                print(hex(addr), idx, res, oty, src_c, src_r, file = fp)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_c].strip(), file = fp)
                with open(path_r, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_r].strip(), file = fp)

        if len(self.type2) > 0:
            print('Type II', file = fp)
            for addr in self.type2:
                idx, res, oty, src_c, src_r = self.type2[addr]
                print(hex(addr), idx, res, oty, src_c, src_r, file = fp)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_c].strip(), file = fp)
                with open(path_r, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_r].strip(), file = fp)

        if len(self.type3) > 0:
            print('Type III', file = fp)
            for addr in self.type3:
                res, oty, src_c, src_r = self.type3[addr]
                print(hex(addr), res, oty, src_c, src_r, file = fp)
                if src_c:
                    path_c, line_c = src_c
                    with open(path_c, errors='ignore') as f:
                        lines = f.readlines()
                        print(lines[line_c].strip(), file = fp)
                else:
                    print(None, file = fp)
                if src_r:
                    path_r, line_r = src_r
                    with open(path_r, errors='ignore') as f:
                        lines = f.readlines()
                        print(lines[line_r].strip(), file = fp)
                else:
                    print(None, file = fp)

        if len(self.type4) > 0:
            print('Type IV', file = fp)
            for addr in self.type4:
                res, oty, src_c, src_r = self.type4[addr]
                print(hex(addr), res, oty, src_c, src_r, file = fp)
                if src_c:
                    path_c, line_c = src_c
                    with open(path_c, errors='ignore') as f:
                        lines = f.readlines()
                        print(lines[line_c].strip(), file = fp)
                else:
                    print(None, file = fp)
                if src_r:
                    path_r, line_r = src_r
                    with open(path_r, errors='ignore') as f:
                        lines = f.readlines()
                        print(lines[line_r].strip(), file = fp)
                else:
                    print(None, file = fp)

        if len(self.type5) > 0:
            print('Type V', file = fp)
            for addr in self.type5:
                idx, res, oty, src_c, src_r = self.type5[addr]
                print(hex(addr), idx, res, oty, src_c, src_r, file = fp)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_c].strip(), file = fp)
                with open(path_r, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_r].strip(), file = fp)

        if len(self.type6) > 0:
            print('Type VI', file = fp)
            for addr in self.type6:
                idx, res, oty, src_c, src_r = self.type6[addr]
                print(hex(addr), idx, res, oty, src_c, src_r, file = fp)
                path_c, line_c = src_c
                path_r, line_r = src_r
                with open(path_c, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_c].strip(), file = fp)
                with open(path_r, errors='ignore') as f:
                    lines = f.readlines()
                    print(lines[line_r].strip(), file = fp)

def save_report_stat(path, stat):
    num_s = ["I", "II", "III", "IV", "V", "VI"]
    f = open(path, "w")
    for i in range(len(stat)):
        print("Type %s : %d" % (num_s[i], stat[i]), file = f)
    f.close()

# FIXME
def load_gt(bench_dir, match_dir, bin_path):
    prog = match_gt.main(bench_dir, bin_path, match_dir)
    return prog

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

# Disassembly Error

def compare_disasm_errors(report, prog_c, prog_r):
    ins_addrs_c = set(prog_c.Instrs.keys())
    ins_addrs_r = set(prog_r.Instrs.keys())

    print('Instr from GT:', len(ins_addrs_c))
    print('Instr from Tool:', len(ins_addrs_r))
    ins_addrs = ins_addrs_c.intersection(ins_addrs_r)

    report.record_disasm_result(len(ins_addrs_c), len(ins_addrs))

    return ins_addrs

# Symbolization Error

def get_lbl_section(report, prog, ins_addr, cmpt):
    lbls = cmpt.get_labels()
    if len(lbls) > 1:
        report.warning(ins_addr, 'More than one labels')
        addr = lbls[0].Address
        return prog.get_section(addr)
    else:
        addr = lbls[0].Address
        return prog.get_section(addr)

# Atomic && GOTOFF
def check_TypeI_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    if cmpt_c.is_ms():
        if cmpt_r.is_ms():
            if cmpt_c != cmpt_r: # FP
                report.report_type1(ins_c.Address, idx, 'FP', 'O-', src_c, src_r)
        else: # FN
            report.report_type1(ins_c.Address, idx, 'FN', 'O4', src_c, src_r)
    else: # FP
        report.report_type1(ins_c.Address, idx, 'FP', 'O5', src_c, src_r)

# Composite && GOTOFF
def check_TypeII_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    if cmpt_c.is_ms():
        if cmpt_r.is_ms():
            if cmpt_c != cmpt_r: # FP
                sec_c = get_lbl_section(report, prog_c, ins_c.Address, cmpt_c)
                sec_r = get_lbl_section(report, prog_r, ins_r.Address, cmpt_r)
                if prog_c.is_valid_addr(cmpt_c.Value):
                    if prog_r.is_reloc_defined(cmpt_r.Value) and cmpt_r.Terms[0].Address == cmpt_r.Value:
                        report.report_type2(ins_c.Address, idx, 'FP', 'O12', src_c, src_r)
                    elif sec_c != sec_r:
                        if sec_r == '.text':
                            report.report_type2(ins_c.Address, idx, 'FP', 'O11', src_c, src_r)
                        else:
                            report.report_type2(ins_c.Address, idx, 'FP', 'O10', src_c, src_r)
                    else:
                        report.report_type2(ins_c.Address, idx, 'FP', 'O-', src_c, src_r)
                else:
                    if sec_c != sec_r:
                        report.report_type2(ins_c.Address, idx, 'FP', 'O9', src_c, src_r)
                    else:
                        report.report_type2(ins_c.Address, idx, 'FP', 'O-', src_c, src_r)
        else: # FN
            if not prog_c.is_valid_addr(cmpt_c.Value):
                report.report_type2(ins_c.Address, idx, 'FN', 'O1', src_c, src_r)
            else:
                sec_c = get_lbl_section(report, prog_c, ins_c.Address, cmpt_c)
                if prog_c.is_linker_generated_section(sec_c):
                    report.report_type2(ins_c.Address, idx, 'FN', 'O13', src_c, src_r)
                else:
                    report.report_type2(ins_c.Address, idx, 'FN', 'O-', src_c, src_r)
    else: # XXX: FP
        report.report_type2(ins_c.Address, idx, 'FP', 'O3', src_c, src_r)

# Atomic && LABEL
def check_TypeV_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    if cmpt_c.is_ms():
        if cmpt_r.is_ms():
            if cmpt_c != cmpt_r: # FP
                report.report_type5(ins_c.Address, idx, 'FP', 'O-', src_c, src_r)
        else: # FN
            report.report_type5(ins_c.Address, idx, 'FN', 'O2', src_c, src_r)
    else: # FP
        report.report_type5(ins_c.Address, idx, 'FP', 'O3', src_c, src_r)

# Composite && LABEL
def check_TypeVI_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx):
    src_c = ins_c.Path, ins_c.Line
    src_r = ins_r.Path, ins_r.Line
    if cmpt_c.is_ms():
        if cmpt_r.is_ms():
            if cmpt_c != cmpt_r: # FP
                sec_c = get_lbl_section(report, prog_c, ins_c.Address, cmpt_c)
                sec_r = get_lbl_section(report, prog_r, ins_r.Address, cmpt_r)
                if prog_c.is_valid_addr(cmpt_c.Value):
                    if prog_r.is_reloc_defined(cmpt_r.Value) and cmpt_r.Terms[0].Address == cmpt_r.Value:
                        report.report_type6(ins_c.Address, idx, 'FP', 'O12', src_c, src_r)
                    elif sec_c != sec_r:
                        if sec_r == '.text':
                            report.report_type6(ins_c.Address, idx, 'FP', 'O11', src_c, src_r)
                        else:
                            report.report_type6(ins_c.Address, idx, 'FP', 'O10', src_c, src_r)
                    else:
                        report.report_type6(ins_c.Address, idx, 'FP', 'O-', src_c, src_r)
                else:
                    if sec_c != sec_r:
                        report.report_type6(ins_c.Address, idx, 'FP', 'O9', src_c, src_r)
                    else:
                        report.report_type6(ins_c.Address, idx, 'FP', 'O-', src_c, src_r)
        else: # FN
            if not prog_c.is_valid_addr(cmpt_c.Value):
                report.report_type6(ins_c.Address, idx, 'FN', 'O1', src_c, src_r)
            else:
                sec_c = get_lbl_section(report, prog_c, ins_c.Address, cmpt_c)
                if prog_c.is_linker_generated_section(sec_c):
                    report.report_type6(ins_c.Address, idx, 'FN', 'O13', src_c, src_r)
                else:
                    report.report_type6(ins_c.Address, idx, 'FN', 'O-', src_c, src_r)
    else: # XXX: FP
        report.report_type6(ins_c.Address, idx, 'FP', 'O3', src_c, src_r)

def check_ins_error(report, prog_c, prog_r, ins_c, ins_r, idx):
    cmpt_c = ins_c.Components[idx]
    cmpt_r = ins_r.Components[idx]

    if cmpt_c.is_ms():
        if cmpt_c.is_composite():
            if cmpt_c.Terms[0].Ty == LblTy.GOTOFF: # Type II
                check_TypeII_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)
            else: # Type VI
                check_TypeVI_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)
        else:
            if cmpt_c.Terms[0].Ty == LblTy.GOTOFF: # Type I
                check_TypeI_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)
            else: # Type V
                check_TypeV_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)
    else: # FP
        if cmpt_r.is_composite():
            if cmpt_r.Terms[0].Ty == LblTy.GOTOFF: # Type II
                check_TypeII_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)
            else: # Type VI
                check_TypeVI_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)
        else:
            if cmpt_r.Terms[0].Ty == LblTy.GOTOFF: # Type I
                check_TypeI_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)
            else: # Type V
                check_TypeV_error(report, prog_c, prog_r, ins_c, ins_r, cmpt_c, cmpt_r, idx)

def get_cmpt_list(ins_c, ins_r):
    cmpt_c = ins_c.get_components()
    cmpt_r = ins_r.get_components()
    cmpts = list(set(cmpt_c + cmpt_r))
    cmpts.sort()
    return cmpts

def check_table_errors(report, prog_c, prog_r):
    print('# Tables to check:', len(prog_c.Tables))
    data_addrs = set(prog_r.Data.keys())

    for tbl_addr in prog_c.Tables:
        table = prog_c.Tables[tbl_addr]
        entry_addr = tbl_addr
        is_fn = False
        for i in range(len(table.Entries)):
            data_c = table.Entries[i]
            src_c = data_c.Path, data_c.Line
            cmpt_c = data_c.Component
            if entry_addr not in data_addrs: # FN
                if cmpt_c.is_composite(): # Type IV
                    report.report_type4(entry_addr, 'FP', 'O7', src_c, None)
                else: # Type III
                    report.report_type3(entry_addr, 'FP', 'O7', src_c, None)
                is_fn = True
            else:
                data_r = prog_r.Data[entry_addr]
                src_r = data_r.Path, data_r.Line
                cmpt_r = data_c.Component
                if cmpt_c != cmpt_r: # FP
                    if cmpt_c.is_composite(): # TYPE IV
                        report.report_type4(entry_addr, 'FP', 'O-', src_c, src_r)
                    else: # TYPE III
                        report.report_type3(entry_addr, 'FP', 'O-', src_c, src_r)
                data_addrs.remove(entry_addr)
            entry_addr += table.EntrySize
        if is_fn:
            continue
        while True:
            if entry_addr in prog_c.Tables:
                break
            if entry_addr not in data_addrs:
                break
            data_r = prog_r.Data[entry_addr]
            src_r = data_r.Path, data_r.Line
            cmpt_r = data_r.Component
            if cmpt_r.is_ms(): # FP
                if cmpt_r.is_composite(): # Type IV
                    report.report_type4(entry_addr, 'FP', 'O8', None, src_r)
                else: # Type III
                    report.report_type3(entry_addr, 'FP', 'O8', None, src_r)
                data_addrs.remove(entry_addr)
            else:
                break
            entry_addr += table.EntrySize

    # XXX: Detect O6

def compare_symbolization_errors(report, prog_c, prog_r, ins_addrs):
    print('# Instrs to check:', len(ins_addrs))
    for addr in ins_addrs:
        ins_c = prog_c.Instrs[addr]
        ins_r = prog_r.Instrs[addr]

        cmpts = get_cmpt_list(ins_c, ins_r)
        for idx in cmpts:
            check_ins_error(report, prog_c, prog_r, ins_c, ins_r, idx)

    check_table_errors(report, prog_c, prog_r)

def compare(prog_c, prog_r):
    report = Report()
    ins_addrs = compare_disasm_errors(report, prog_c, prog_r)
    compare_symbolization_errors(report, prog_c, prog_r, ins_addrs)
    return report

TOOLS = ['retro', 'ramblr', 'ddisasm']

def test_vs_tools(bench_dir, match_dir):
    for package, arch, compiler, pie, opt in gen_options():
        print(package, arch, compiler, pie, opt)
        base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        strip_dir = os.path.join(base_dir, 'stripbin')
        for bin_name in os.listdir(strip_dir):
            bin_path = os.path.join(strip_dir, bin_name)
            print(bin_name)
            tools = {}
            for tool in TOOLS:
                tool_asm = os.path.join(base_dir, tool, bin_name + '.s')
                if not os.path.exists(tool_asm):
                    print(tool, 'Not Exists')
                    tools[tool] = None
                    continue
                size = os.path.getsize(tool_asm)
                if size == 0:
                    print(tool, '0 size')
                    tools[tool] = None
                    continue
                prog_r = load_tool(tool, tool_asm, bin_path)
                tools[tool] = prog_r

            prog_retro = tools['retro']
            prog_ramblr = tools['ramblr']
            prog_ddisasm = tools['ddisasm']
            if prog_retro is not None and prog_ramblr is not None:
                print('Compare retro vs ramblr')
                report = compare(prog_retro, prog_ramblr)
                report.report()
            if prog_retro is not None and prog_ddisasm is not None:
                print('Compare retro vs ddisasm')
                report = compare(prog_retro, prog_ddisasm)
                report.report()
            if prog_ramblr is not None and prog_ddisasm is not None:
                print('Compare ramblr vs ddisasm')
                report = compare(prog_ramblr, prog_ddisasm)
                report.report()

def test_vs_gt(bench_dir, match_dir, mode, result_dir):
    for package, arch, compiler, pie, opt in gen_options():
        base_dir = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        result_base = os.path.join(result_dir, package, arch, compiler, pie, opt)
        stat_path = os.path.join(result_base, "stat")
        if os.path.exists(stat_path):
            continue
        os.system("mkdir -p %s" % result_base)
        stdout_f = os.path.join(result_base, "out")
        stdout_f = open_file(stdout_f)
        stats = [0, 0, 0, 0, 0, 0]

        print(package, arch, compiler, pie, opt)
        print(package, arch, compiler, pie, opt, file = stdout_f)
        strip_dir = os.path.join(base_dir, 'stripbin')
        bin_dir = os.path.join(base_dir, 'bin')
        match_base = os.path.join(match_dir, package, arch, compiler, pie, opt)
        for bin_name in os.listdir(bin_dir):
            try:
                bin_path = os.path.join(bin_dir, bin_name)
                strip_path = os.path.join(strip_dir, bin_name)
                match_path = os.path.join(match_base, bin_name + '.json')
                binstat_path = os.path.join(result_base, bin_name + ".stat")
                if os.path.exists(binstat_path):
                    continue
                bstat_f = open(binstat_path, "w")
                print(bin_name, file = stdout_f)
                # Load GT
                prog_loaded = False
                for tool in TOOLS:
                    try:
                        tool_asm = os.path.join(base_dir, tool, bin_name + '.s')
                        if not os.path.exists(tool_asm):
                            print(tool, 'Not Exists', file = stdout_f)
                            continue
                        size = os.path.getsize(tool_asm)
                        if size == 0:
                            print(tool, '0 size', file = stdout_f)
                            continue
                        if size > 1024 * 1024 * 1024:
                            print(tool, 'big size', file = stdout_f)
                            continue
                        prog_r = load_tool(tool, tool_asm, strip_path)
                        if not prog_loaded:
                            prog_c = load_gt(bench_dir, match_path, bin_path)
                            prog_loaded = True
                        print('Compare GT vs', tool, file = stdout_f)
                        report = compare(prog_c, prog_r)
                        stat = [
                            len(report.type1),
                            len(report.type2),
                            len(report.type3),
                            len(report.type4),
                            len(report.type5),
                            len(report.type6)
                        ]
                        for i in range(6):
                            stats[i] += stat[i]
                        print(stats)
                        print(tool, file=bstat_f)
                        print(stat, file=bstat_f)
                        report.save_report_data(stdout_f)
                    except Exception as e:
                        err_f = os.path.join(result_base, "exception")
                        err_f = open_file(err_f)
                        print(os.path.join(bin_dir, bin_name), "%s error" % tool, file = err_f)
                        traceback.print_exc(file = err_f)
                        pass
                bstat_f.close()
            except Exception as e:
                bstat_f.close()
                err_f = os.path.join(result_base, "exception")
                err_f = open_file(err_f)
                print(os.path.join(bin_dir, bin_name), "gt error", file = err_f)
                traceback.print_exc(file = err_f)
                pass
        stdout_f.close()
        stat_path = os.path.join(result_base, "stat")
        save_report_stat(stat_path, stats)

def main(bench_dir, match_dir, mode, result_dir):
    if mode == 'gt':
        test_vs_gt(bench_dir, match_dir, mode, result_dir)
    elif mode == 'tool':
        test_vs_tools(bench_dir, match_dir)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    match_dir = sys.argv[2]
    mode = sys.argv[3]
    result_dir = sys.argv[4]
    main(bench_dir, match_dir, mode, result_dir)
