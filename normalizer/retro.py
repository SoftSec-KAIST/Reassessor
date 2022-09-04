import re
import capstone
import os
from normalizer.tool_base import NormalizeTool
from lib.parser import parse_att_asm_line, ReasmLabel, parse_set_directive

HUGE_FILE_SIZE = 1024*1024*1024*10

class NormalizeRetro(NormalizeTool):
    def __init__(self, bin_path, reassem_path):
        super().__init__(bin_path, reassem_path, retro_mapper, capstone.CS_OPT_SYNTAX_ATT, label_func = retro_label_func)

retro_huge_addr_set = set()

def retro_label_to_addr(label):
    if label.startswith('.LC'):
        addr = int(label[3:], 16)
    elif label.startswith('.LLC'):
        addr = int(label[4:], 16)
    elif label.startswith('.L'):
        if '_' in label:
            addr = int(label.split('_')[-1],16)
        else:
            addr = int(label[2:], 16)
    else:
        addr = 0
    return addr

def retro_label_func(label):
    global retro_huge_addr_set
    addr = retro_label_to_addr(label)
    if addr > 0 and addr in retro_huge_addr_set:
        return addr
    return 0

def create_huge_addr_set(reassem_path):
    global retro_huge_addr_set
    additional_file =  reassem_path.replace('retrowrite', 'retrowrite_expand')
    import os
    if os.path.isfile(additional_file):
        print(' [+] read huge addr set %s'%(additional_file))
        import time
        tic = time.perf_counter()
        retro_huge_addr_set = set(retro_label_to_addr(line.strip()[:-1]) for line in open(additional_file))
        toc = time.perf_counter()
        print(' [+] complete to make huge addr set (%d) %0.4f'%(len(retro_huge_addr_set), toc-tic))
    else:
        print(' [-] %s does not exist'%(additional_file))

def retro_mapper(reassem_path, tokenizer):
    result = []
    addr = -1

    fsize = os.path.getsize(reassem_path)
    if fsize > HUGE_FILE_SIZE:
        create_huge_addr_set(reassem_path)
        pass

    with open(reassem_path, errors='ignore') as f:
        for idx, line in enumerate(f):
            terms = line.split('#')[0].split()
            if len(terms) == 0:
                continue
            if re.search('^.*:$', terms[0]):
                xaddr = retro_label_to_addr(terms[0][:-1])
                if xaddr > 0:
                    addr = xaddr

                if addr > 0:
                    #Too many labels might cause OOM errors
                    #We exclude obvious label if file size is larger than 10G
                    #Instead we memory the addresses where labels are defined
                    if fsize > HUGE_FILE_SIZE:
                        if xaddr == addr:
                            pass
                        else:
                            result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                    else:
                        result.append(ReasmLabel(terms[0][:-1], addr, idx+1))
                else:
                    result.append(ReasmLabel(terms[0][:-1], 0, idx+1))
                continue
            elif terms[0] in ['.long', '.quad']:
                expr = ''.join(terms[1:])
                #if re.search('.[+|-]', expr):
                if [term for term in re.split('[+|-]', expr) if re.match('[._a-zA-Z]', term) ]:
                    result.append(tokenizer.parse_data(terms[0] + ' ' + expr, addr, idx+1))
            elif terms[0] in ['.set']:
                # ex) .set FUN_804a3f0, . - 10
                # ex) .set L_0, 0
                label_addr, num = parse_set_directive(line, retro_label_to_addr)
                result.append(ReasmSetLabel(terms[1][:-1], label_addr, num, idx+1))
            elif re.search('^[a-zA-Z].*', terms[0]):
                asm_line = ' '.join(terms)
                result.append(tokenizer.parse(asm_line, addr, idx+1))
            else:
                continue
            addr = -1

    if fsize > HUGE_FILE_SIZE:
        print(' [+] complete to map the code: %s'%(reassem_path))
    return result




import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='normalize_gt')
    parser.add_argument('bin_path', type=str)
    parser.add_argument('reassem_path', type=str)
    parser.add_argument('save_file', type=str)
    args = parser.parse_args()

    retro = NormalizeRetro(args.bin_path, args.reassem_path)
    retro.normalize_inst()
    retro.normalize_data()
    retro.save(args.save_file)

