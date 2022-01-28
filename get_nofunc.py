import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
import json
import os
import glob
import sys
from utils import gen_options, RE_FUNC, RE_INST
import re
import multiprocessing
import subprocess

func_list = 0

def get_dwarf_loc(filename):
    dwarf_loc_map = {}

    def process_file(filename):
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)

            if not elffile.has_dwarf_info():
                print('  file has no DWARF info')
                return

            dwarfinfo = elffile.get_dwarf_info()
            for CU in dwarfinfo.iter_CUs():
                line_program = dwarfinfo.line_program_for_CU(CU)
                if line_program is None:
                    continue
                line_entry_mapping(line_program)

    def line_entry_mapping(line_program):
        lp_entries = line_program.get_entries()
        for lpe in lp_entries:
            if not lpe.state or lpe.state.file == 0:
                continue

            filename = lpe_filename(line_program, lpe.state.file)
            if lpe.state.address not in dwarf_loc_map.keys():
                dwarf_loc_map[lpe.state.address] = []
            dwarf_loc_map[lpe.state.address].append([filename, lpe.state.line])

    def lpe_filename(line_program, file_index):
        lp_header = line_program.header
        file_entries = lp_header["file_entry"]

        file_entry = file_entries[file_index - 1]
        dir_index = file_entry["dir_index"]

        if dir_index == 0:
            return file_entry.name.decode()

        directory = lp_header["include_directory"][dir_index - 1]
        return os.path.join(directory, file_entry.name).decode()

    process_file(filename)
    return dwarf_loc_map

def get_loc_by_func_name(locs, fname):
    result = []
    for loc in locs:
        if loc[1] == fname:
            result.append(loc)
    if len(result) == 0:
        return None
    else:
        return result


def get_func_code(instructions, instruction_addrs, address, size):
    try:
        result = []
        idx = instruction_addrs.index(address)
        curr = address
        while True:
            if curr >= address + size:
                break
            inst = instructions[curr]
            result.append(inst)
            curr += inst.size
        return result
    except:
        print("Disassembly failed. Impossible")
        exit()


def src_get_insts(lines, max_len):
    result = []
    is_rep = False
    for line in lines[1:]:
        if len(result) >= max_len:
            break
        if RE_FUNC.match(line):
            ''' Next function '''
            break
        if RE_INST.match(line):
            op = line.split()[0]
            if op.startswith("rep") and len(line.split()) == 1:
                is_rep = True
                result.append(line)
            elif is_rep:
                is_rep = False
                continue
            elif op.startswith("cld"):
                if len(line.split()) > 1 and line.split()[1].startswith("rep"):
                    result.append("\tcld")
                    result.append("\trep")
                else:
                    result.append("\tcld")
            else:
                result.append(line)
    return result

def is_same_jump(op1, op2):
    # only first 3 bytes
    # http://www.unixwiz.net/techtips/x86-jumps.html
    jumps = [
        ["jo"],
        ["jno"],
        ["js"],
        ["jns"],
        ["je", "jz"],
        ["jne", "jnz"],
        ["jb", "jna", "jc"],
        ["jnb", "jae", "jnc"],
        ["jbe", "jna"],
        ["ja", "jnb"],
        ["jl", "jng"],
        ["jge", "jnl"],
        ["jle", "jng"],
        ["jg", "jnl"],
        ["jp", "jpe"],
        ["jnp", "jpo"],
        ["jcx", "jec"]
    ]
    for jump in jumps:
        if op1 in jump and op2 in jump:
            return True
    return False

def is_semantically_same(op1, op2):
    opcodes = [
        ["mov", "lea"],
        ["shl", "sal"],
        ["ret", "rep"], # retq == rep retn
    ]
    for opcode in opcodes:
        if op1 in opcode and op2 in opcode:
            return True
    return False

def is_semantically_nop(inst):
    try:
        if inst.mnemonic.startswith("nop"):
            return True
        elif inst.mnemonic[:3] == "lea" and inst.mnemonic != 'leave':
            operands = inst.op_str.split(", ")
            return operands[0] == "(" + operands[1] + ")"
        elif inst.mnemonic[:3] == "mov":
            operands = inst.op_str.split(", ")
            return operands[0] == operands[1]
    except:
        assert False, 'unexpected instruction '
    return False

def is_semantically_nop_str(inst_str):
    try:
        new_inst_str = inst_str.split('#')[0]
        mnemonic = new_inst_str.split()[0]

        if mnemonic.startswith("nop"):
            return True
        if mnemonic[:3] == "lea" and mnemonic != 'leave':
            operand1 = new_inst_str.split(',')[0].split()[-1]
            operand2 = new_inst_str.split(',')[1].split()[-1]
            return operand1 == "(" + operand2 + ")"
        elif mnemonic[:3] == "mov" and not mnemonic.startswith("movs"):
            operand1 = new_inst_str.split(',')[0].split()[-1]
            operand2 = new_inst_str.split(',')[1].split()[-1]
            return operand1 == operand2
    except:
        assert False, 'unexpected instruction %s' % new_inst_str
    return False



def find_match_func(src_files, locs, func_code):
    #Debug
    if len(locs) == 1:
        return locs
    matched_locs = []
    mov_lea = ["mov", "lea"]
    for loc in locs:
        line = int(loc[1].split("@")[1])
        lines = src_files[loc[0]].split("\n")[line-1:]
        src_insts = src_get_insts(lines, len(func_code))
        src_insts_len = len(src_insts)
        match_cnt = 0
        bin_nop_cnt = 0
        src_nop_cnt = 0
        for idx, inst in enumerate(func_code):
            if src_insts_len - src_nop_cnt <= idx - bin_nop_cnt:
                break
            src_idx = idx - bin_nop_cnt + src_nop_cnt
            src_op = src_insts[src_idx].split()[0][:3].lower()
            bin_op = inst.mnemonic.lower()[:3]
            #DEBUG
            #print(inst.mnemonic, inst.op_str, '\t', src_insts[src_idx])
            if is_semantically_nop(inst):
                # compile might emit nop code
                if is_semantically_nop_str(src_insts[src_idx]):
                    src_nop_cnt += 1
                bin_nop_cnt += 1
                continue
            while True:
                if src_op == "nop":
                    src_nop_cnt += 1
                    src_idx = idx - bin_nop_cnt + src_nop_cnt
                    if src_idx >= len(src_insts):
                        # bin_op != "nop"
                        # src_op == "nop"
                        # So next loc will be processed
                        break
                    src_op = src_insts[src_idx].split()[0][:3].lower()
                else:
                    break
            if bin_op != src_op:
                if is_semantically_same(src_op, bin_op):
                    match_cnt += 1
                elif src_op[0] == "j" and bin_op[0] == "j" and is_same_jump(src_op, bin_op):
                    match_cnt += 1
                else:
                    #print(hex(inst.address), inst.mnemonic, [inst.op_str], src_insts[src_idx])
                    break
            else:
                match_cnt += 1
        #DEBUG
        #print(match_cnt, len(func_code), bin_nop_cnt)
        #print(func_code[-1].mnemonic, func_code[-1].op_str)
        if match_cnt == len(func_code) - bin_nop_cnt:
            matched_locs.append(loc)
    if len(matched_locs) == 0:
        return None
    else:
        return matched_locs

def select_src_candidate(dwarf_loc, faddress, src_files, res, debug_loc_paths):
    def find_first_debug_loc(path, line):
        lines = src_files[path].split("\n")[line:]
        for line in lines:
            if RE_FUNC.match(line):
                return None
            line_s = line.strip()
            if line_s.startswith(".loc"):
                return line_s.split()
        return None

    def check_debug_loc(debug_loc, dwarf_infos):
        debug_path, debug_line = debug_loc
        for dwarf_info in dwarf_infos:
            path, line = dwarf_info
            if debug_path in path and debug_line == line:
                return True
        return False

    try:
        dwarf_infos = dwarf_loc[faddress]
    except:
        return None
    for candidate_path, candidate_line in res:
        candidate_linei = int(candidate_line.split("@")[1])
        ret = find_first_debug_loc(candidate_path, candidate_linei)
        if not ret:
            continue
        debug_loc_path = debug_loc_paths[candidate_path][int(ret[1])]
        debug_loc_line = int(ret[2])
        if check_debug_loc([debug_loc_path, debug_loc_line], dwarf_infos):
            return [candidate_path, candidate_line]

    return None

def triage_spec_candidates(binname, loc_candidates):
    res = []
    for loc in loc_candidates:
        if "/asm/%s/" % binname in loc[0]:
            res.append(loc)
    return res

def get_src_files(bench_dir, src_files, loc_candidates):
    for loc_path, _ in loc_candidates:
        if loc_path not in src_files.keys():
            loc_path_full = os.path.join(bench_dir, loc_path)
            f = open(loc_path_full, errors='ignore')
            src_files[loc_path] = f.read()
    return src_files

def get_loc_by_file_id(src_files, debug_loc_paths, loc_candidates):
    FILEID_RE = re.compile("[\n][ \t]*\.file[ \t]*[0-9]{1,}[ \t]*.*")
    for loc_path, _ in loc_candidates:
        if loc_path in debug_loc_paths.keys():
            continue
        src_file = src_files[loc_path]
        debug_loc_paths[loc_path] = {}
        for fileid in FILEID_RE.findall(src_file):
            fileid_s = fileid.split()
            _id = int(fileid_s[1])
            _path = fileid_s[-1][1:-1]
            debug_loc_paths[loc_path][_id] = _path
    return debug_loc_paths

def get_end_of_func(src_files, loc):
    path, line = loc[0]
    src_file = src_files[path].split("\n")
    line = int(line.split("@")[1])
    c = line
    for l in src_file[line-1:]:
        if l.strip().startswith(".cfi_endproc"):
            break
        c += 1
    new_loc = [[path, line, c]]
    return new_loc

def run(args):
    bench_dir, func_path, result_dir, options = args
    package, arch, compiler, pie, opt = options

    prefix = "/".join([package, arch, compiler, pie, opt])
    print(prefix)
    binpaths = glob.glob(os.path.join(bench_dir, prefix) + "/bin/*")
    debug_loc_paths = {}
    src_files = {}
    for binpath in binpaths:
        locs = func_list[prefix]
        funcs = []   # [funcname, address, size] list

        tt = "_".join([package, arch, compiler, pie, opt, os.path.basename(binpath)])
        os.system("objdump -t -f %s | grep \"F .text\" | sort > /tmp/xx%s" % (binpath, tt))

        for line in open("/tmp/xx" + tt):
            l = line.split()
            fname = l[-1]
            faddress = int(l[0], 16)
            fsize = int(l[4], 16)
            cmd = ['c++filt', fname]
            try:
                loc_candidates = locs[fname]
                if package == "spec_cpu2006":
                    binname = os.path.basename(binpath)
                    loc_candidates = triage_spec_candidates(binname, loc_candidates)
                if len(loc_candidates) == 0:
                    if subprocess.check_output(cmd).decode()[:-1] == fname:
                        funcs.append(fname)
            except:
                if subprocess.check_output(cmd).decode()[:-1] == fname:
                    funcs.append(fname)
                pass

        print(funcs)

        json_dir = os.path.join(result_dir, prefix)
        if not os.path.exists(json_dir):
            os.system("mkdir -p %s" % json_dir)
        json_path = json_dir + "/" + os.path.basename(binpath)
        with open(json_path, "w") as json_file:
            json_file.write('\n'.join(funcs))

def main(bench_dir, func_path, result_dir):
    global func_list
    func_list = json.load(open(func_path, "rb"))

    args = []
    for package, arch, compiler, pie, opt in gen_options():
        args.append((bench_dir, func_path, result_dir, [package, arch, compiler, pie, opt]))

    p = multiprocessing.Pool(84)
    p.map(run, args)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    func_path = sys.argv[2]
    result_dir = sys.argv[3]
    # Assume these parameters are always valid
    main(bench_dir, func_path, result_dir)
