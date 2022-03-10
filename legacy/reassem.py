import multiprocessing
import os
import sys
import glob

from lib.utils import gen_options

def go(args):
    path_list, options, tool = args
    [package, arch, compiler, pie, opt] = options
    (bin_dir, out_dir) = path_list

    bin_dir = bin_dir + '/' +  '/'.join(options) + '/bin'
    reassem_dir = out_dir + '/' +  '/'.join(options) + '/' + tool
    log_dir = './reassem_script/log/'  +  '/'.join(options) + '/' + tool

    bin_list = glob.glob(bin_dir + '/*')

    #log_path = 'log/reassem_%s_%s.txt' % (tool, '_'.join(options))

    #os.system('mkdir -p %s' % reassem_dir)
    #os.system('mkdir -p %s' % log_dir)

    for bin_path in bin_list:
        if os.path.getsize(bin_path):
            bin_name = os.path.basename(bin_path)

            reassem_path = reassem_dir + '/' + bin_name + '.s'
            log_path = log_dir + '/' + bin_name + '.txt'

            if tool in ['ddisasm']:
                cmd = './reassem_script/do_%s.sh %s %s > %s 2>&1 '%(tool, bin_dir, reassem_dir, log_path)
                print(cmd)
                cmd = './reassem_script/do_%s.sh %s %s '%(tool, bin_dir, reassem_dir, )
                os.system(cmd)
            else:
                cmd = './reassem_script/do_%s.sh %s %s > %s 2>&1 '%(tool, bin_path, reassem_path, log_path)
                print(cmd)
                cmd = './reassem_script/do_%s.sh %s %s '%(tool, bin_path, reassem_path)
                os.system(cmd)

def main(path_list):
    options = []

    for package, arch, compiler, pie, opt in gen_options():
        a = [package, arch, compiler, pie, opt]
        options.append((path_list, a, "ddisasm"))
        #options.append((path_list, a, "ramblr"))
        #options.append((path_list, a, "retro_sym"))

    pool = multiprocessing.Pool(84)
    pool.map(go, options)


if __name__ == '__main__':
    bin_dir = sys.argv[1]
    result_dir = sys.argv[2]
    path_list = (bin_dir, result_dir)
    main(path_list)
