import multiprocessing
import os
import sys

from utils import gen_options

def go(args):
    path_list, options, mode = args
    (bench_dir, match_dir, ms_dir, reassem_dir, pickle_dir) = path_list
    base = "/".join([options[0], options[1], options[2]])
    #composite_path = "/home/bbbig/tmp/matched2/composite_ms/"
    #composite_path = "/home/hskim/data/sok/reassessor/composite_ms/"
    composite_path = ms_dir
    composite_path = os.path.join(composite_path, options[0], options[1], options[2])
    if options[0] == "spec_cpu2006":
        composite_path = os.path.join(composite_path, options[3], options[4])

    cmd = [
        "python3",
        "save_prog.py",
        bench_dir, #"/data2/benchmark/",
        #"/home/bbbig/tmp/matched2/",
        match_dir, #"/home/hskim/data/sok/reassessor/matched/",
        pickle_dir, #"/home/hskim/data/sok/reassessor/pickles/",
        mode,
        options[0],
        options[1],
        options[2],
        options[3],
        options[4],
        composite_path,
        reassem_dir, #"/home/hskim/data/sok/reassem/result/",
        ">>",
        "log/res_new_%s_%s" % (mode, "_".join(options))
    ]

    cmd = " ".join(cmd)
    print(cmd)
    os.system(cmd)

def main(path_list):
    options = []

    for package, arch, compiler, pie, opt in gen_options():
        a = [package, arch, compiler, pie, opt]
        options.append((path_list, a, "ddisasm"))
        options.append((path_list, a, "ramblr"))
        options.append((path_list, a, "retro_sym"))
        #options.append((path_list, a, "gt"))

    pool = multiprocessing.Pool(84)
    pool.map(go, options)


if __name__ == '__main__':
    bench_dir = sys.argv[1]
    match_dir = sys.argv[2]
    ms_dir = sys.argv[3]
    reassem_dir = sys.argv[4]
    pickle_dir = sys.argv[5]
    path_list = (bench_dir, match_dir, ms_dir, reassem_dir, pickle_dir)
    main(path_list)
