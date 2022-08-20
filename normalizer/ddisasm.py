import capstone
import re
import os

from lib.parser import parse_intel_asm_line, DATA_DIRECTIVE, SKIP_DIRECTIVE, ReasmInst, ReasmData, ReasmLabel, ReasmSetLabel
from normalizer.tool_base import NormalizeTool

SYM_BLK = ['__rela_iplt_end']

def ddisasm_label_to_addr(label):
    # '.L_587dd0@GOTPCREL'
    label = label.split('@')[0]
    if label.startswith('FUN_'):
        addr = int(label[4:],16)
    elif label.startswith('.L_'):
        if label.endswith('_END'):
            addr = int(label[3:-4], 16)
        else:
            addr = int(label[3:], 16)
    else:
        addr = 0

    return addr



class NormalizeDdisasm(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, ddisasm_mapper, capstone.CS_OPT_SYNTAX_INTEL)

def ddisasm_set_label_parser(line, label_to_addr):

    label = line.split(',')[0].split()[1]
    exprs = line.split(',')[1].split()

    new_exprs = []
    new_labels = []
    for expr in exprs:
        if expr.isdigit() or expr in ['+', '-', '*'] or expr.startswith('0x'):
            new_exprs.append(expr)
        elif expr[0] in ['.'] or expr[0].isalpha():
            new_exprs.append('0')
            new_labels.append(expr)
        else:
            assert False, 'Unknown expression'

    num = eval(''.join(new_exprs))

    assert len(new_labels) < 2, 'Invalid expression'

    xaddr = -1
    if new_labels:
        if '.' == new_labels[0]:
            # .set FUN_804a3f0, . - 10
            # FUN_804a3f0 = . - 10
            # . = FUN_804a3f0 - (- 10)
            xaddr = label_to_addr(label) - num
        else:
            xaddr = label_to_addr(new_labels[0])

    return xaddr, num

def ddisasm_mapper(reassem_path, tokenizer):
    result = []
    addr = -1
    is_linker_gen = False

    asm_file = os.path.basename(reassem_path)

    with open(reassem_path) as f:
        unknown_label_idx = -1
        for idx, line in enumerate(f):
            terms = line.split('#')[0].split()
            if len(terms) == 0:
                continue

            if terms[0] in ['.align', '.globl', '.hidden', '.weak', '.intel_syntax', '.type', 'nop']:
                pass
            elif terms[0].startswith('.cfi_'):
                pass
            elif terms[0] in ['.section']:
                # Ddisam 1.5.3 sometimes does not create section name
                # .section
                # 416.gamess and 434.zeusmp
                if asm_file in ['416.gamess.s', '434.zeusmp.s']:
                    is_linker_gen = False
                elif len(terms) > 1 and terms[1] not in ['.fini', '.init', '.plt.got']:
                    is_linker_gen = False
                else:
                    is_linker_gen = True
            elif terms[0] in ['.text', '.data', '.bss']:
                is_linker_gen = False
            elif terms[0] in ['.set']:
                # ex) .set FUN_804a3f0, . - 10
                # ex) .set L_0, 0
                addr, num = ddisasm_set_label_parser(line, ddisasm_label_to_addr)
                result.append(ReasmSetLabel(terms[1][:-1], addr, num, idx+1))
            elif re.search('^.*:$', line):
                xaddr = ddisasm_label_to_addr(terms[0][:-1])
                if xaddr > 0:
                    addr = xaddr
                    if unknown_label_idx + 1 == idx and isinstance(result[-1], ReasmLabel):
                        prev_label, _, prev_idx = result[-1]
                        assert prev_idx == unknown_label_idx + 1
                        result[-1] = ReasmLabel(prev_label, addr, prev_idx)
                if addr > 0:
                    result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                else:
                    result.append(ReasmLabel(terms[0][:-1], 0, idx+1))
                    unknown_label_idx = idx

                continue
            elif is_linker_gen or terms[0] in SKIP_DIRECTIVE:
                continue
            elif terms[0].startswith('.'):
                pass
            elif terms[0] in ['nop']:
                pass
            else:
                addr = int(re.search('^([0-9a-f]*)', terms[0][:-1])[0],16)
                if unknown_label_idx + 1 == idx and isinstance(result[-1], ReasmLabel):
                    prev_label, _, prev_idx = result[-1]
                    assert prev_idx == unknown_label_idx + 1
                    result[-1] = ReasmLabel(prev_label, addr, prev_idx)
                if terms[1] in DATA_DIRECTIVE:
                    if terms[1] in ['.long', '.quad']:
                        expr = ''.join(terms[2:])
                        #if re.search('.[+|-]', expr):
                        if [term for term in re.split('[+|-]', expr) if re.match('[._a-zA-Z]', term) ]:
                            result.append(tokenizer.parse_data(terms[1] + ' ' + expr, addr, idx+1))
                else:
                    asm_line = ' '.join(terms[1:])
                    result.append(tokenizer.parse(asm_line, addr, idx+1))

            addr = -1
    #ddisasm debug option has some bugs so we store label to additional assembly files
    additional_file =  reassem_path.replace('ddisasm_debug', 'ddisasm_debug_expand')
    if os.path.isfile(additional_file):
        with open(additional_file) as f:
            for line in f:
                if re.search('^.*:$', line):
                    terms = line.split('#')[0].split()
                    xaddr = ddisasm_label_to_addr(terms[0][:-1])
                    if xaddr > 0:
                        result.append(ReasmLabel(terms[0][:-1], xaddr, 0))



    return result


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='normalize_ddisasm')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('reassem_path', type=str)
    parser.add_argument('save_file', type=str)
    args = parser.parse_args()

    ddisasm = NormalizeDdisasm(args.bin_path, args.reassem_path)
    ddisasm.normalize_inst()
    ddisasm.normalize_data()
    ddisasm.save(args.save_file)

