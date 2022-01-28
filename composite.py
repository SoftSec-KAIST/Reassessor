import os, sys
from utils import *
from asm_types import *
import pickle
import json
import multiprocessing

class Findings:
    def __init__(self):
        self.objrel_in_codes = {}
        self.objrel_in_data = {}

        self.composite_in_codes = {}
        self.composite_in_data = {}

def check_instr(f, textrange, ins):
    saddr, eaddr = textrange
    for cmpt in ins.Components:
        if cmpt.is_ms() and cmpt.is_composite():
            '''
            if os.path.exists(ins.Path):
                with open(ins.Path, 'rb') as srcfile:
                    lines = srcfile.readlines()
                line = lines[ins.Line].strip()
            else:
                line = ''
            '''
            if cmpt.Ty == CmptTy.OBJREL:
                is_code = False
                for t in cmpt.Terms:
                    if isinstance(t, Label):
                        lbl = t.Address
                        is_code = is_code or saddr <= lbl and lbl < eaddr
                f.objrel_in_codes[ins.Address] = [is_code, ins.Path, ins.Line]
            else:
                is_code = True
                for t in cmpt.Terms:
                    if isinstance(t, Label):
                        lbl = t.Address
                        is_code = is_code and saddr <= lbl and lbl < eaddr
                f.composite_in_codes[ins.Address] = [is_code, ins.Path, ins.Line, cmptTyToStr(cmpt.Ty)]

def check_data(f, textrange, data):
    saddr, eaddr = textrange
    cmpt = data.Component
    if cmpt.is_ms() and cmpt.is_composite():
        '''
        if os.path.exists(data.Path):
            with open(data.Path, 'rb') as srcfile:
                lines = srcfile.readlines()
            line = lines[data.Line].strip()
        else:
            line = ''
        '''
        if cmpt.Ty == CmptTy.OBJREL:
            is_code = False
            for t in cmpt.Terms:
                if isinstance(t, Label):
                    lbl = t.Address
                    is_code = is_code or saddr <= lbl and lbl < eaddr
            f.objrel_in_data[data.Address] = [is_code, data.Path, data.Line]
        else:
            is_code = True
            for t in cmpt.Terms:
                if isinstance(t, Label):
                    lbl = t.Address
                    is_code = is_code and saddr <= lbl and lbl < eaddr
            f.composite_in_data[data.Address] = [is_code, data.Path, data.Line, cmptTyToStr(cmpt.Ty)]

def check(elf, prog):
    f = Findings()
    text, data = get_text(elf)
    saddr = text
    eaddr = text + len(data)
    textrange = (saddr, eaddr)
    for addr in prog.Instrs:
        ins = prog.Instrs[addr]
        check_instr(f, textrange, ins)
    for addr in prog.Data:
        data = prog.Data[addr]
        check_data(f, textrange, data)
    return f

def test(args):
    bench_dir, pickle_dir, triage_dir, options = args
    package, arch, compiler, pie, opt = options
    print(package, arch, compiler, pie, opt)
    bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
    pickle_base = os.path.join(pickle_dir, package, arch, compiler, pie, opt)
    triage_base = os.path.join(triage_dir, package, arch, compiler, pie, opt)
    if not os.path.exists(triage_base):
        os.system('mkdir -p %s' % triage_base)
    bin_dir = os.path.join(bench_base, 'bin')
    for name in os.listdir(bin_dir):
        pickle_path = os.path.join(pickle_base, 'gt', name + '.p3')
        if not os.path.exists(pickle_path):
            continue
        pickle_file = open(pickle_path, 'rb')
        prog = pickle.load(pickle_file)
        pickle_file.close()
        bin_path = os.path.join(bin_dir, name)
        elf = load_elf(bin_path)
        f = check(elf, prog)
        triage_path = os.path.join(triage_base, name)
        with open(triage_path, 'w') as triage_file:
            j = {
                    'ObjRel_Code': f.objrel_in_codes,
                    'ObjRel_Data': f.objrel_in_data,
                    'Composite_Code': f.composite_in_codes,
                    'Composite_Data': f.composite_in_data
                    }
            triage_file.write(json.dumps(j))

def main(bench_dir, pickle_dir, triage_dir):
    args = []
    for package, arch, compiler, pie, opt in gen_options():
        args.append((bench_dir, pickle_dir, triage_dir, [package, arch, compiler, pie, opt]))
    p = multiprocessing.Pool(84)
    p.map(test, args)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    stat_dir = sys.argv[2]
    #pickle_dir = '/home/bbbig/tmp/pickles4'
    triage_dir = sys.args[3]
    #triage_dir = '/home/soomink/triage3'
    main(bench_dir, pickle_dir, triage_dir)
