from capstone.x86 import *

from asm_types import *

def parse_att_asm_line(line):
    src_inst = line.strip()
    if src_inst.lower().startswith("nop"):
        return []
    if " " in src_inst:
        src_inst = src_inst.split(" ", 1)
        if src_inst[0].startswith("rep"):
            s = src_inst[1].split(" ", 1)
            src_inst[0] += " " + s[0]
            if len(s) > 1:
                src_inst[1] = s[1]
            else:
                src_inst[1] = ''
        src_inst[1] = src_inst[1].split(",")
    else:
        src_inst = [src_inst, []]
    for i in range(len(src_inst[1])):
        src_inst[1][i] = src_inst[1][i].strip()
    return src_inst

def parse_att_components(has_label, get_label_expr, parse_expr, insn, src, relocs):
    digits = "-0123456789"
    insn_operands = insn.operands
    result = []
    if len(insn_operands) == 2 and len(src[1]) == 1:
        result.append(Component())
        insn_operands = insn_operands[1:]
    for idx, i in enumerate(insn_operands):
        s = src[1][idx]
        if i.type == X86_OP_REG:
            result.append(Component())
        elif i.type == X86_OP_IMM:
            is_pcrel = False
            if insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL):
                is_pcrel = True
            s = get_label_expr(s)
            if has_label(s, relocs):
                value = i.imm
                terms = parse_expr(s, value, relocs)
                result.append(Component(terms, value, is_pcrel))
            else:
                result.append(Component())
        elif i.type == X86_OP_MEM:
            disp = s.split("(")[0]
            is_pcrel = False
            if len(disp) > 0:
                s = get_label_expr(disp)
                if has_label(s, relocs):
                    if i.mem.base == X86_REG_RIP:
                        value = insn.address + insn.size + i.mem.disp
                        is_pcrel = True
                    else:
                        value = i.mem.disp
                    terms = parse_expr(s, value, relocs)
                    result.append(Component(terms, value, is_pcrel))
                else:
                    result.append(Component())
            else:
                result.append(Component())
    return result
