import re
import capstone

from lib.parser import ReasmLabel, DATA_DIRECTIVE, SKIP_DIRECTIVE, parse_set_directive
from normalizer.tool_base import NormalizeTool


RE_INST = re.compile('[ \t]{1,}[A-Za-z0-9].*')
RE_FUNC = re.compile('[A-Za-z_][0-9A-Za-z_]+[:]')


class NormalizeRamblr(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, ramblr_mapper, capstone.CS_OPT_SYNTAX_ATT)

def ramblr_mapper(reassem_path, tokenizer):

    result = []
    addr = -1
    is_linker_gen = False
    visited_addr = set()
    with open(reassem_path) as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if line == '':
                continue

            if line.startswith('#'):
                addr_ = do_comment(line)
                if addr_ is not None:
                    addr = addr_
                continue

            terms = line.split('#')[0].split()
            if len(terms) == 0:
                continue

            if terms[0] == '.section':
                section = line.split()[1]
                if section not in ['.fini', '.init', '.plt.got']:
                    is_linker_gen = False
                else:
                    is_linker_gen = True
                addr = -1
                continue

            if is_linker_gen or terms[0] in SKIP_DIRECTIVE:
                continue

            if re.search('^.*:$', terms[0]):
                xaddr = ramblr_label_to_addr(terms[0][:-1])
                if xaddr > 0:
                    addr = xaddr

                if addr > 0:
                    result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                else:
                    result.append(ReasmLabel(terms[0][:-1], 0, idx+1))

                continue

            assert addr > 0

            if terms[0] in DATA_DIRECTIVE:
                if terms[0] in ['.long', '.quad']:
                    expr = ''.join(terms[1:])
                    #if re.search('.[+|-]', expr):
                    if [term for term in re.split('[+|-]', expr) if re.match('[._a-zA-Z]', term) ]:
                        result.append(tokenizer.parse_data(terms[0] + ' ' + expr, addr, idx+1))
                addr += get_data_size(line)

            elif terms[0] in ['.set']:
                # ex) .set FUN_804a3f0, . - 10
                # ex) .set L_0, 0
                label_addr, num = parse_set_directive(line, ramblr_label_to_addr)
                result.append(ReasmSetLabel(terms[1][:-1], label_addr, num, idx+1))
            else:
                # ramblr sometimes creates duplicated code
                if addr in visited_addr:
                    continue
                visited_addr.add(addr)
                asm_line = ' '.join(terms)
                result.append(tokenizer.parse(asm_line, addr, idx+1))
                addr = -1

    return result

def ramblr_label_to_addr(label):
    if label.startswith('sub_'):
        # ramblr makes exceptional symbols cgc binary (clang 6)
        if 'entry_info_list' == label[4:]:
            return 0
        addr = int(label[4:], 16)
    else:
        addr = 0
    return addr

def do_comment(line):
    if line.startswith('#Procedure'):
        return None
    elif line.startswith('# 0x') and ':' in line:
        addr = int(line[2:].split(':')[0], 16)
        return addr
    elif line.startswith('# data @'):
        addr = int(line[8:], 16)
        return addr
    else:
        print(line)
        print('exit 1')
        #sys.exit(-1)

def get_data_size(line):
    directive = line.split()[0]
    if directive.startswith('.byte'):
        return 1
    elif directive.startswith('.short'):
        return 2
    elif directive.startswith('.long'):
        return 4
    elif directive.startswith('.quad'):
        return 8
    elif directive.startswith('.zero'):
        n = int(line.split()[1])
        return n
    elif directive.startswith('.string') or directive.startswith('.asciz'):
        token = '"'.join(line.split('"')[1:])[:-1]
        return len(token) + 1
    elif directive.startswith('.ascii'):
        token = '"'.join(line.split('"')[1:])[:-1]
        return len(token)

    print(line)
    sys.exit(-1)


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='normalize_ramblr')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('reassem_path', type=str)
    parser.add_argument('save_file', type=str)
    args = parser.parse_args()

    ramblr = NormalizeRamblr(args.bin_path, args.reassem_path)
    ramblr.normalize_inst()
    ramblr.normalize_data()
    ramblr.save(args.save_file)
