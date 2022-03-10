import os
import glob
import json
import sys
from lib.utils import gen_options, RE_FUNC
import multiprocessing

def get_src_paths(asmpath):
    srcs = []
    for i in range(20):
        t = "*/" * i
        srcs += glob.glob(asmpath + t + "*.s")
    return srcs

def run(arg):
    result = {}
    bench_dir, json_dir, options = arg
    package, arch, compiler, pie, opt = options


    prefix = "/".join([package, arch, compiler, pie, opt])
    print(prefix)

    asmpath = os.path.join(bench_dir, prefix) + "/asm/"
    srcs = get_src_paths(asmpath)

    result[prefix] = {}
    for src in srcs:
        cnt = 0
        for line in open(src, errors='ignore'):
            cnt += 1
            line = str(line)
            if RE_FUNC.match(line):
                path = src[len(bench_dir):]
                fname = line.split(":")[0]
                if fname not in result[prefix].keys():
                    result[prefix][fname] = []
                result[prefix][fname].append([path, "line@%d" % cnt])

    json_path_dir = os.path.join(json_dir, prefix)
    json_path = os.path.join(json_path_dir, "result.json")

    if not os.path.exists(json_path_dir):
        os.system("mkdir -p %s" % json_path_dir)

    print(json_path)
    with open(json_path, 'w') as fp:
        json.dump(result, fp)


def collect_loc_candidates(bench_dir, asm_root):

    srcs = get_src_paths(asm_root)
    result = {}


    for src in srcs:
        cnt = 0
        for line in open(src, errors='ignore'):
            cnt += 1
            line = str(line)
            if RE_FUNC.match(line):
                path = src[len(bench_dir):]
                #print(path)
                fname = line.split(":")[0]
                if fname not in result.keys():
                    result[fname] = []
                result[fname].append([path, "line@%d" % cnt])

    return result


def main(bench_dir, json_dir):
    args = []
    for package, arch, compiler, pie, opt in gen_options():
        args.append((bench_dir, json_dir, [package, arch, compiler, pie, opt]))

    p = multiprocessing.Pool(84)
    p.map(run, args)


if __name__ == '__main__':
    bench_dir = sys.argv[1]
    json_dir = sys.argv[2]
    # Assume these parameters are always valid
    main(bench_dir, json_dir)
