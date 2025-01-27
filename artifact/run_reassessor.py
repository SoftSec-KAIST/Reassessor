from collections import namedtuple
import glob, os, sys
import multiprocessing

BuildConf = namedtuple('BuildConf', ['target', 'input_root', 'sub_dir', 'output_path', 'arch', 'pie', 'package', 'bin'])


def gen_option(input_root, output_root, package, blacklist, whitelist):
    ret = []
    cnt = 0
    for arch in ['x64']:
        for comp in ['clang-10', 'clang-13', 'gcc-11', 'gcc-13']:
            for popt in ['pie']:
                for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                    for lopt in ['bfd', 'gold']:
                        sub_dir = '%s/%s/%s_%s'%(package, comp, opt, lopt)
                        input_dir = '%s/%s'%(input_root, sub_dir)
                        for target in glob.glob('%s/bin/*'%(input_dir)):

                            filename = os.path.basename(target)
                            binpath = '%s/bin/%s'%(input_dir, filename)

                            if package in ['coreutils-9.1']:
                                # 1 (opt) * 2 (comp) * 2 (linker) = 4
                                if comp in ['gcc-11', 'gcc-13']:
                                    if opt in ['ofast']:
                                        if filename in ['seq']:
                                            continue

                            if package in ['spec_cpu2006']:
                                # 5 (opt) * 4 (comp) * 2 (linker) =  40
                                if filename in ['416.gamess'] and opt not in ['o0']:
                                    continue
                                # 1 (opt) * 1 (comp) * 2 (linker) = 2
                                if filename in ['453.povray'] and opt in ['ofast'] and comp in ['gcc-13']:
                                    continue

                            if package in ['spec_cpu2006']:
                                # 1 (opt) * 1 (comp) * 2 (linker) = 2
                                if filename in ['511.povray_r'] and opt in ['ofast'] and comp in ['gcc-13']:
                                    continue

                            out_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                            if blacklist and filename in blacklist:
                                continue
                            if whitelist and filename not in whitelist:
                                continue

                            ret.append(BuildConf(target, input_root, sub_dir, out_dir, arch, popt, package, binpath))

                            cnt += 1
    return ret

def job(conf, reset=False):

    from reassessor.normalizer.gt import NormalizeGT

    norm_dir = '%s/norm_db'%(conf.output_path)
    gt_norm_path = '%s/gt.db'%(norm_dir)
    gt_func_path = '%s/func.json'%(norm_dir)
    gt_endbr_path = '%s/endbr64.json'%(norm_dir)

    if not reset and os.path.exists(gt_func_path):
        return

    if conf.package in ['spec_cpu2017', 'spec_cpu2006']:
        gt = NormalizeGT(conf.target, '%s/%s/asm/%s'%(conf.input_root, conf.sub_dir, os.path.basename(conf.target)), reloc_file='', build_path = '')
    else:
        gt = NormalizeGT(conf.target, '%s/%s/asm'%(conf.input_root, conf.sub_dir), reloc_file='', build_path = conf.input_root)


    gt.normalize_data()

    os.system('mkdir -p %s'%(norm_dir))
    gt.save(gt_norm_path)
    gt.save_func_dict(gt_func_path)

    # record ENDBR64 addresses
    with open(gt_endbr_path, 'w') as fd:
        for key in sorted(gt.instructions.keys()):
            if(gt.instructions[key].mnemonic == 'endbr64'):
                fd.write('%x\n'%(key))

    print('[+] %s'%(conf.target))
    sys.stdout.flush()



def run(input_root, output_root, package, core=1, blacklist=None, whitelist=None):
    if package not in ['coreutils-9.1', 'binutils-2.40', 'spec_cpu2017', 'spec_cpu2006']:
        return False

    config_list = gen_option(input_root, output_root, package, blacklist, whitelist)

    if core and core > 1:
        p = multiprocessing.Pool(core)
        p.map(job, [(conf) for conf in config_list])
    else:
        for conf in config_list:
            job(conf)


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('benchmark', type=str, help='benchmark path')
    parser.add_argument('output', type=str, help='output path')
    parser.add_argument('--package', type=str, help='Package')
    parser.add_argument('--core', type=int, default=1, help='Number of cores to use')
    parser.add_argument('--blacklist', nargs='+')
    parser.add_argument('--whitelist', nargs='+')

    args = parser.parse_args()

    if args.package:
        run(args.benchmark, args.output, args.package, args.core, args.blacklist, args.whitelist)
    else:
        for package in ['coreutils-9.1', 'binutils-2.40', 'spec_cpu2006', 'spec_cpu2017']:
            run(args.benchmark, args.output, package, args.core, args.blacklist, args.whitelist)
