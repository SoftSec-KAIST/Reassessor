import capstone
import pickle
import re

from lib.parser import parse_intel_asm_line, DATA_DIRECTIVE, SKIP_DIRECTIVE, ReasmInst, ReasmData, ReasmLabel
from normalizer.match_tool import NormalizeTool

SYM_BLK = ['__rela_iplt_end']

def ddisasm_label_to_addr(label):
    if label.startswith('FUN_'):
        addr = int(label[4:])
    elif label.startswith('.L_'):
        addr = int(label[3:], 16)
    else:
        addr = 0

    return addr



class NormalizeDdisasm(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, ddisasm_mapper, ddisasm_label_to_addr, capstone.CS_OPT_SYNTAX_INTEL)

def ddisasm_mapper(reassem_path, tokenizer):
    result = []
    addr = -1
    is_linker_gen = False
    with open(reassem_path) as f:
        for idx, line in enumerate(f):

            terms = line.split('#')[0].split()
            if len(terms) == 0:
                continue

            if terms[0] in ['.align', '.globl', '.hidden', '.weak', '.intel_syntax', '.type', 'nop']:
                pass
            elif terms[0].startswith('.cfi_'):
                pass
            elif terms[0] in ['.section']:
                if terms[1] not in ['.fini', '.init', '.plt.got']:
                    is_linker_gen = False
                else:
                    is_linker_gen = True
            elif terms[0] in ['.text', '.data', '.bss']:
                is_linker_gen = False
            elif re.search('^.*:$', line):
                xaddr = ddisasm_label_to_addr(terms[0][:-1])
                if xaddr > 0:
                    addr = xaddr
                elif addr > 0:
                    result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                continue
            elif is_linker_gen or terms[0] in SKIP_DIRECTIVE:
                continue
            elif terms[0].startswith('.'):
                pass
            elif terms[0] in ['nop']:
                pass
            else:
                addr = int(re.search('^([0-9a-f]*)', terms[0][:-1])[0],16)

                if terms[1] in DATA_DIRECTIVE:
                    if terms[1] in ['.long', '.quad']:
                        op_str = ''.join(terms[2:])
                        if re.search('.[+|-]', op_str):
                            result.append(tokenizer.parse_data(terms[1] + ' ' + op_str, addr, idx+1))
                else:
                    asm_line = ' '.join(terms[1:])
                    result.append(tokenizer.parse(asm_line, addr, idx+1))

            addr = -1

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

    with open(args.save_file, 'wb') as f:
        pickle.dump(ddisasm.prog, f)
