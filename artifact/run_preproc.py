from collections import namedtuple
import glob, os
import multiprocessing

BuildConf = namedtuple('BuildConf', ['target', 'input_root', 'sub_dir', 'reassem_dir', 'output_dir', 'arch', 'pie', 'package', 'bin', 'stripbin'])

def single_run(target):
    input_root = './dataset'
    output_root = './output'
    package, arch, _, popt, _ = target.split('/')[-7:-2]
    sub_dir = '/'.join(target.split('/')[-7:-2])

    filename = os.path.basename(target)
    output_dir = '%s/%s/%s'%(output_root, sub_dir, filename)
    conf = BuildConf(target, input_root, sub_dir, output_dir, arch, popt, package)

    job(conf, reset=True)

def gen_option(input_root, reassem_root, output_root, package):
    ret = []
    cnt = 0
    for arch in ['x86', 'x64']:
        for comp in ['clang', 'gcc']:
            for popt in ['pie', 'nopie']:
                for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                    for lopt in ['bfd', 'gold']:
                        sub_dir = '%s/%s/%s/%s/%s-%s'%(package, arch, comp, popt, opt, lopt)
                        input_dir = '%s/%s'%(input_root, sub_dir)
                        for target in glob.glob('%s/reloc/*'%(input_dir)):

                            filename = os.path.basename(target)

                            binpath = '%s/bin/%s'%(input_dir, filename)
                            stripbin = '%s/stripbin/%s'%(input_dir, filename)
                            reassem_dir = '%s/%s/%s'%(reassem_root, sub_dir, filename)
                            output_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                            ret.append(BuildConf(target, input_root, sub_dir, reassem_dir, output_dir, arch, popt, package, binpath, stripbin))

                            cnt += 1
    return ret

def job(conf, reset=False):

    ramblr_output = conf.reassem_dir+'/ramblr.s'
    retrowrite_output = conf.reassem_dir+'/retrowrite.s'
    ddisasm_output = conf.reassem_dir+'/ddisasm.s'

    reassem_list = ['ramblr', 'retrowrite', 'ddisasm']
    reassem_dict = dict()

    for reassem in reassem_list:
        reassem_dict[reassem] = True

    if conf.pie != 'pie':
        reassem_dict['retrowrite'] = False
        if not reset and os.path.exists(ramblr_output):
            reassem_dict['ramblr'] = False
        if not reset and os.path.exists(ddisasm_output):
            reassem_dict['ddisasm'] = False
    else:
        reassem_dict['ramblr'] = False
        if conf.arch != 'x64':
            reassem_dict['retrowrite'] = False
        else:
            if not reset and os.path.exists(retrowrite_output):
                reassem_dict['retrowrite'] = False
        if not reset and os.path.exists(ddisasm_output):
            reassem_dict['ddisasm'] = False

    options = ''
    bRun = False
    for reassem in reassem_list:
        if not reassem_dict[reassem]:
            options += ' --no-%s'%(reassem)
        else:
            print(reassem)
            bRun = True

    if bRun:
        print('python3 ../reassessor/preprocessing.py %s %s %s --bin_path %s --stripbin %s'%(conf.target, conf.output_dir, options, conf.bin, conf.stripbin))
        os.system('python3 ../reassessor/preprocessing.py %s %s %s --bin_path %s --stripbin %s'%(conf.target, conf.output_dir, options, conf.bin, conf.stripbin))

        #from reassessor.preprocessing import Preprocessing
        #preproc = Preprocessing(conf.target, conf.output_dir, arch=conf.arch, pie=conf.pie, bin_path=conf.bin, stripbin_path=conf.stripbin)
        #preproc.run(reset=False, bDdisasm, bRamblr, bRetro)


def run(package, core=1, reset=False):
    if package not in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
        return False
    input_root= './dataset'
    reassem_root = './reassem'
    output_root = './output'
    config_list = gen_option(input_root, reassem_root, output_root, package)

    if core and core > 1:
        p = multiprocessing.Pool(core)
        p.starmap(job, [(conf,reset) for conf in config_list])
    else:
        for conf in config_list:
            job(conf, reset)


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--package', type=str, help='Package')
    parser.add_argument('--core', type=int, default=1, help='Number of cores to use')
    parser.add_argument('--target', type=str)
    parser.add_argument('--reset', action='store_true')

    args = parser.parse_args()

    if args.target:
        single_run(args.target)
    elif args.package:
        run(args.package, args.core, args.reset)
    else:
        for package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            run(package, args.core, args.reset)


