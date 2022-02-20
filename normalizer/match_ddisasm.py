import capstone
from capstone.x86 import *
import sys
import pickle

from lib.asm_types import *
from lib.utils import *

from normalizer.match_tool import NormalizeTool, DATA_DIRECTIVE, SKIP_DIRECTIVE

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
        super().__init__(bin_path, reassem_path, ddisasm_map_func, ddisasm_label_to_addr, capstone.CS_OPT_SYNTAX_INTEL)


def ddisasm_map_func(reassem_path):
    addressed_lines = ddisasm_mapper(reassem_path)

    addressed_asms = []
    addressed_data = []

    for addr, line, idx in addressed_lines:
        tokens = line.split()
        if tokens[0] in DATA_DIRECTIVE:

           if tokens[0] in ['.quad', '.long']:

                exprs_str = ''.join(tokens[1:])
                has_label = False
                for term in re.split('\-|\+', exprs_str):
                    if re.search('^[._a-zA-Z]', term):
                        has_label = True

                if has_label:
                    if tokens[0] == '.quad':
                        addressed_data.append((addr, exprs_str, 8, idx))
                    elif tokens[0] == '.long':
                        addressed_data.append((addr, exprs_str, 4, idx))
                    else:
                        print(line)
                        print('exit 3')
                        assert 0
        else:
            tokens = parse_ddisasm_asm_line(line)
            if len(tokens) > 0:
                addressed_asms.append((addr, tokens, idx))

    return addressed_asms, addressed_data

def ddisasm_mapper(reassem_path):
    result = []
    addr = -1
    is_linker_gen = False
    with open(reassem_path) as f:
        temp_label_list = []
        for idx, line in enumerate(f):
            line = line.strip()
            if line == '':
                continue
            if line.startswith('#'):
                continue

            token = line.split()[0]

            if token in ['.align', '.globl', '.hidden', '.weak', '.intel_syntax', '.type', 'nop']:
                continue
            elif token.startswith('.cfi_'):
                continue

            if token in ['.section']:
                section = line.split()[1]
                if section not in ['.fini', '.init', '.plt.got']:
                    is_linker_gen = False
                else:
                    is_linker_gen = True
                    continue

                #temp_label_list = [(line, idx)]
                temp_label_list = []
                continue
            elif token in ['.text', '.data', '.bss']:
                is_linker_gen = False
                #temp_label_list = [(line, idx)]
                temp_label_list = []
                continue


            if is_linker_gen or token in SKIP_DIRECTIVE:
                continue

            if line.startswith('FUN_') and line.endswith(':'):
                line = line.split(':')[0]
                addr = int(line[4:])
            elif line.startswith('.L_') and line.endswith(':'):
                line = line.split(':')[0]
                addr = int(line[3:], 16)
            elif line.endswith(':'):
                temp_label_list.append((line, idx))
                continue
            else:
                #print(line)
                addr = int(re.search('^([0-9a-f]*)', line)[0],16)
                line = ':'.join(line.split(':')[1:]).strip()

            for (prev_line, prev_idx) in temp_label_list:
                result.append((addr, prev_line, prev_idx))

            temp_label_list = []

            result.append((addr, line, idx))

    return result

def parse_ddisasm_asm_line(line):
    prev = line.split(',')[0]
    args = line.split(',')[1:]

    if line in ['nop']:
        opcode = 'nop'
        arg1 = ''
        return []
    elif prev.split()[0] in ['rep', 'repe', 'repz', 'repne', 'repnz']:
        opcode = ' '.join(prev.split()[:2])
        arg1 = ' '.join(prev.split()[2:])
    else:
        opcode = prev.split()[0]
        arg1 = ' '.join(prev.split()[1:])

    ret = [opcode,[]]
    if arg1:
        ret[1].append(arg1)
        for arg in args:
            ret[1].append(arg)
    return ret

if __name__ == '__main__':
    bin_path = sys.argv[1]
    reassem_path = sys.argv[2]
    pickle_path = sys.argv[3]

    ddisasm = NormalizeDdisasm(bin_path, reassem_path)
    ddisasm.normalize_inst()
    ddisasm.normalize_data()

    with open(pickle_path, 'wb') as f:
        pickle.dump(ddisasm.prog, f)
