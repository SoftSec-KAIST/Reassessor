import multiprocessing
import os
import sys
import glob

from utils import gen_options

def go(args):
    path_list, options, tool = args
    [package, arch, compiler, pie, opt] = options
    (reassem_dir, out_dir) = path_list
    asm_dir = reassem_dir + '/' +  '/'.join(options) + '/' + tool
    bin_dir = out_dir + '/' +  '/'.join(options) + '/' + tool

    asm_list = glob.glob(asm_dir + '/*.s')

    log_path = 'log/compile_%s_%s.txt' % (tool, '_'.join(options))
    for asm_path in asm_list:
        if os.path.getsize(asm_path):
            asm_name = os.path.basename(asm_path)
            bin_name = asm_name[:-2]
            bin_path = bin_dir + '/' + bin_name

            if arch == 'x86':
                script = 'c_x86'
            else:
                script = 'c_x64'

            if 'spec' in package:
                if int(asm_name.split('.')[0]) in [444, 447, 450, 453, 471, 473, 483]:
                    script = 'cpp'
                elif int(asm_name.split('.')[0]) in [410, 416, 434, 435, 436, 437, 454, 459, 465, 481]:
                    script = 'fort'

            cmd = './compile_script/compile_%s.sh %s %s >> %s 2>&1 '%(script, asm_path, bin_path, log_path)
            #print(cmd)
            os.system(cmd)
    '''
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
    '''

def main(path_list):
    options = []

    for package, arch, compiler, pie, opt in gen_options():
        a = [package, arch, compiler, pie, opt]
        options.append((path_list, a, "ddisasm"))
        options.append((path_list, a, "ramblr"))
        options.append((path_list, a, "retro_sym"))

    pool = multiprocessing.Pool(84)
    pool.map(go, options)


if __name__ == '__main__':
    reassem_dir = sys.argv[1]
    result_dir = sys.argv[2]
    path_list = (reassem_dir, result_dir)
    main(path_list)
