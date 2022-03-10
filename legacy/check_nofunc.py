import sys, os
from utils import *

def main(bench_dir, stat_dir):
    names = set()
    for package, arch, compiler, pie, opt in gen_options():
        bench_base = os.path.join(bench_dir, package, arch, compiler, pie, opt)
        stat_base = os.path.join(stat_dir, package, arch, compiler, pie, opt)
        bin_dir = os.path.join(bench_base, 'stripbin')
        for name in os.listdir(bin_dir):
            stat_file = os.path.join(stat_base, name)
            with open(stat_file) as f:
                for line in f.readlines():
                    names.add(line.strip())

    print(names)

if __name__ == '__main__':
    bench_dir = sys.argv[1]
    #bench_dir = '/data2/benchmark'
    stat_dir = sys.argv[2]
    #stat_dir = '/home/bbbig/tmp/nofunc'
    main(bench_dir, stat_dir)
