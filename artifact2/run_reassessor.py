from collections import namedtuple
import glob, os, sys
import multiprocessing

BuildConf = namedtuple('BuildConf', ['target', 'input_root', 'sub_dir', 'output_path', 'arch', 'pie', 'package', 'bin'])

def single_run(target, bDocker=False):
    input_path = '/data4/benchmark'
    output_path = '/data4/output'
    package, _, _ = target.split('/')[-5:-2]
    arch = 'x64'
    popt = 'pie'
    sub_dir = '/'.join(target.split('/')[-5:-2])

    filename = os.path.basename(target)
    out_dir = '%s/%s/%s'%(output_path, sub_dir, filename)
    conf = BuildConf(target, input_path, sub_dir, out_dir, arch, popt, package, target)

    if not bDocker:
        job(conf, reset=True)
    else:
        docker_job(conf)


def gen_option(input_root, reassem_root, output_root, package, blacklist, whitelist):
    ret = []
    cnt = 0
    for arch in ['x64']:
        for comp in ['clang-13', 'gcc-11']:
            for popt in ['pie']:
                for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                    for lopt in ['bfd', 'gold']:
                        sub_dir = '%s/%s/%s_%s'%(package, comp, opt, lopt)
                        input_dir = '%s/%s'%(input_root, sub_dir)
                        for target in glob.glob('%s/bin/*'%(input_dir)):

                            filename = os.path.basename(target)
                            binpath = '%s/bin/%s'%(input_dir, filename)

                            reassem_dir = '%s/%s/%s'%(reassem_root, sub_dir, filename)
                            out_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                            if blacklist and filename in blacklist:
                                continue
                            if whitelist and filename not in whitelist:
                                continue

                            ret.append(BuildConf(target, input_root, sub_dir, out_dir, arch, popt, package, binpath))

                            cnt += 1
    return ret

def job(conf, reset=False):
    reassem_dict = dict()
    '''
    ramblr_output = conf.reassem_path+'/reassem/ramblr.s'
    retrowrite_output = conf.reassem_path+'/reassem/retrowrite.s'
    ddisasm_output = conf.reassem_path+'/reassem/ddisasm.s'

    if os.path.exists(ramblr_output):
        reassem_dict['ramblr'] = ramblr_output
    if os.path.exists(retrowrite_output):
        reassem_dict['retrowrite'] = retrowrite_output
    if os.path.exists(ddisasm_output):
        reassem_dict['ddisasm'] = ddisasm_output

    from reassessor.reassessor import Reassessor
    print(conf.target)
    sys.stdout.flush()

    if conf.package in ['spec_cpu2006']:
        reassessor = Reassessor(conf.target, '%s/%s/asm/%s'%(conf.input_root, conf.sub_dir, os.path.basename(conf.target)), conf.output_path, build_path = conf.input_root, bin_path=conf.bin)
    else:
        reassessor = Reassessor(conf.target, '%s/%s/asm'%(conf.input_root, conf.sub_dir), conf.output_path, build_path = conf.input_root, bin_path=conf.bin)

    reassessor.run(reassem_dict)
    '''
    from reassessor.normalizer.gt import NormalizeGT

    norm_dir = '%s/norm_db'%(conf.output_path)
    gt_norm_path = '%s/gt.db'%(norm_dir)
    gt_func_path = '%s/func.json'%(norm_dir)


    if not reset and os.path.exists(gt_func_path):
        #print(gt_func_path + ' already exists')
        return

    print(conf.target)
    if conf.package in ['spec_cpu2017']:
        gt = NormalizeGT(conf.target, '%s/%s/asm/%s'%(conf.input_root, conf.sub_dir, os.path.basename(conf.target)), reloc_file='', build_path = conf.input_root)
    else:
        gt = NormalizeGT(conf.target, '%s/%s/asm'%(conf.input_root, conf.sub_dir), reloc_file='', build_path = conf.input_root)

    gt.normalize_data()


    os.system('mkdir -p %s'%(norm_dir))
    gt.save(gt_norm_path)
    gt.save_func_dict(gt_func_path)

    print(gt_func_path)

    sys.stdout.flush()





def docker_job(conf):
    filename=os.path.basename(conf.target)
    cmd = 'docker run --rm -v %s:/input -v %s:/output reassessor -v %s:/reassem sh -c '%(os.path.abspath(conf.input_root), os.path.abspath(conf.output_path), os.path.abspath(conf.reassem_path))
    cmd += '"python3 -m Reassessor.reassessor.reassessor /input/%s/reloc/%s /input/%s/asm /output/ --build_path /input/ --build_path /input/%s/bin/%s'%(conf.sub_dir, filename, conf.sub_dir, conf.sub_dir, filename)
    if os.path.exists(conf.reassem_path+'/ramblr.s'):
        cmd += ' --ramblr /reassem/ramblr.s'
    if os.path.exists(conf.reassem_path+'/retrowrite.s'):
        cmd += ' --retrowrite /reassem/retrowrite.s'
    if os.path.exists(conf.reassem_path+'/ddisasm.s'):
        cmd += ' --ddisasm /reassem/ddisasm.s'
    cmd += '"'
    print(cmd)
    os.system(cmd)


def run(package, core=1, bDocker=False, blacklist=None, whitelist=None):
    if package not in ['coreutils-9.1', 'binutils-2.40', 'spec_cpu2017']:
        return False
    input_root = '/data4/benchmark'
    reassem_root = '/data4/output'
    output_root = '/data4/output'
    config_list = gen_option(input_root, reassem_root, output_root, package, blacklist, whitelist)

    if core and core > 1:
        p = multiprocessing.Pool(core)
        if not bDocker:
            p.map(job, [(conf) for conf in config_list])
        else:
            p.map(docker_job, [(conf) for conf in config_list])
    else:
        for conf in config_list:
            if not bDocker:
                job(conf)
            else:
                docker_job(conf)


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--package', type=str, help='Package')
    parser.add_argument('--core', type=int, default=1, help='Number of cores to use')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--target', type=str)
    parser.add_argument('--blacklist', nargs='+')
    parser.add_argument('--whitelist', nargs='+')

    args = parser.parse_args()

    if args.target:
        single_run(args.target, args.docker)
    elif args.package:
        run(args.package, args.core, args.docker, args.blacklist, args.whitelist)
    else:
        #for package in ['coreutils-9.1', 'binutils-2.40', 'spec_cpu2017']:
        for package in ['coreutils-9.1', 'binutils-2.40']:
        #for package in ['binutils-2.40']:
        #for package in ['coreutils-9.1']:
        #for package in ['spec_cpu2017']:
            run(package, args.core, args.docker, args.blacklist, args.whitelist)
