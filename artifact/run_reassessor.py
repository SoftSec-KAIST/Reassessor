from collections import namedtuple
import glob, os
import multiprocessing

BuildConf = namedtuple('BuildConf', ['target', 'input_root', 'sub_dir', 'reassem_path', 'output_path', 'arch', 'pie', 'package', 'bin'])

def single_run(target, bDocker=False):
    input_path = './dataset'
    output_path = './output'
    package, arch, _, popt, _ = target.split('/')[-7:-2]
    sub_dir = '/'.join(target.split('/')[-7:-2])

    filename = os.path.basename(target)
    out_dir = '%s/%s/%s'%(output_path, sub_dir, filename)
    conf = BuildConf(target, input_path, sub_dir, out_dir, arch, popt, package)

    if not bDocker:
        job(conf)
    else:
        docker_job(conf)


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

                            reassem_dir = '%s/%s/%s'%(reassem_root, sub_dir, filename)
                            out_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                            ret.append(BuildConf(target, input_root, sub_dir, reassem_dir, out_dir, arch, popt, package, binpath))

                            cnt += 1
    return ret

def job(conf):
    reassem_dict = dict()

    ramblr_output = conf.reassem_path+'/ramblr.s'
    retrowrite_output = conf.reassem_path+'/retrowrite.s'
    ddisasm_output = conf.reassem_path+'/ddisasm.s'

    if os.path.exists(ramblr_output):
        reassem_dict['ramblr'] = ramblr_output
    if os.path.exists(retrowrite_output):
        reassem_dict['retrowrite'] = retrowrite_output
    if os.path.exists(ddisasm_output):
        reassem_dict['ddisasm'] = ddisasm_output

    from reassessor.reassessor import Reassessor

    if conf.package in ['spec_cpu2006']:
        reassessor = Reassessor(conf.target, '%s/%s/asm/%s'%(conf.input_root, conf.sub_dir, os.path.basename(conf.target)), conf.output_path, build_path = conf.input_root, bin_path=conf.bin)
    else:
        reassessor = Reassessor(conf.target, '%s/%s/asm'%(conf.input_root, conf.sub_dir), conf.output_path, build_path = conf.input_root, bin_path=conf.bin)

    reassessor.run(reassem_dict)

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


def run(package, core=1, bDocker=False):
    if package not in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
        return False
    input_root = './dataset'
    reassem_root = './reassem'
    output_root = './output'
    config_list = gen_option(input_root, reassem_root, output_root, package)

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

    args = parser.parse_args()

    if args.target:
        single_run(args.target, args.docker)
    elif args.package:
        run(args.package, args.core, args.docker)
    else:
        for package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            run(package, args.core, args.docker)
