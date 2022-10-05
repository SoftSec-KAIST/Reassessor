from reassessor.reassessor import Reassessor
from reassessor.preprocessing import Preprocessing
from collections import namedtuple
import glob, os
import multiprocessing

BuildConf = namedtuple('BuildConf', ['target', 'input_root', 'sub_dir', 'output_path', 'arch', 'pie', 'package'])

def single_run(target):
    input_path = './dataset'
    output_path = './output'
    package, arch, _, popt, _ = target.split('/')[-7:-2]
    sub_dir = '/'.join(target.split('/')[-7:-2])

    filename = os.path.basename(target)
    out_dir = '%s/%s/%s'%(output_path, sub_dir, filename)
    conf = BuildConf(target, input_path, sub_dir, out_dir, arch, popt, package)

    job(conf)

def gen_option(input_root, output_root, package):
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

                            out_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                            ret.append(BuildConf(target, input_root, sub_dir, out_dir, arch, popt, package))

                            cnt += 1
    return ret

def job(conf, bPreprocessing=True):
    reassem_dict = dict()

    if bPreprocessing:
        preproc = Preprocessing(conf.target, conf.output_path)
        preproc.run(reset=False, bDdisasm=False, bRamblr=False, bRetro=False)

    ramblr_output = conf.output_path+'/reassem/ramblr.s'
    retrowrite_output = conf.output_path+'/reassem/retrowrite.s'
    ddisasm_output = conf.output_path+'/reassem/ddisasm.s'

    if os.path.exists(ramblr_output):
        reassem_dict['ramblr'] = ramblr_output
    if os.path.exists(retrowrite_output):
        reassem_dict['retrowrite'] = retrowrite_output
    if os.path.exists(ddisasm_output):
        reassem_dict['ddisasm'] = ddisasm_output

    if conf.package in ['spec_cpu2006']:
        reassessor = Reassessor(conf.target, '%s/%s/asm/%s'%(conf.input_root, conf.sub_dir, os.path.basename(conf.target)), conf.output_path, conf.input_root)
    else:
        reassessor = Reassessor(conf.target, '%s/%s/asm'%(conf.input_root, conf.sub_dir), conf.output_path, conf.input_root)

    reassessor.run(reassem_dict)

def docker_job(conf, bPreprocessing=True):
    cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor sh -c "/Reassessor/reassesor.py /input/%s/reloc/%s /input/%s/assem /output/ /input/'%(conf.input_root, conf.output_path, conf.sub_dir, os.path.basename(conf.target), conf.sub_dir, os.path.basename(conf.target))
    if bPreprocessing:
        download()
    else:
        if os.path.exists(conf.output_path+'/reassem/ramblr.s'):
            cmd += ' --ramblr /output/reassem/ramblr.s'
        if os.path.exists(conf.output_path+'/reassem/retrowrite.s'):
            cmd += ' --retrowrite /output/reassem/retrowrite.s'
        if os.path.exists(conf.output_path+'/reassem/ddisasm.s'):
            cmd += ' --ddisasm /output/reassem/ddisasm.s'
    cmd += '"'
    os.system(cmd)


def run(package, core=1, bPreprocessing=True, bDocker=False):
    if package not in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
        return False
    input_path = './dataset'
    output_path = './output'
    config_list = gen_option(input_path, output_path, package)

    if core and core > 1:
        p = multiprocessing.Pool(core)
        if not bDocker:
            p.starmap(job, [(conf, bPreprocessing) for conf in config_list])
        else:
            p.starmap(docker_job, [(conf, bPreprocessing) for conf in config_list])
    else:
        for conf in config_list:
            if not bDocker:
                job(conf, bPreprocessing)
            else:
                docker_job(conf, bPreprocessing)


import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--package', type=str, help='Package')
    parser.add_argument('--core', type=int, default=1, help='Number of cores to use')
    parser.add_argument('--no-preprocessing', dest='preprocessing', action='store_false')
    parser.add_argument('--docker', action='store_true')
    parser.add_argument('--target', type=str)

    args = parser.parse_args()

    if args.target:
        single_run(args.target)
    elif args.package:
        run(args.package, args.core, args.preprocessing, args.docker)
    else:
        for package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            run(package, args.core, args.preprocessing, args.docker)


