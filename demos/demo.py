from reassessor.reassessor import Reassessor
from collections import namedtuple
import glob, os
import multiprocessing

BuildConf = namedtuple('BuildConf', ['target', 'input_path', 'output_path', 'arch', 'pie'])

def download():
    pass

def gen_option(input_root, output_root, package):
    ret = []
    for arch in ['x86', 'x64']:
        #for comp in ['clang', 'gcc']:
        for comp in ['gcc']:
            for popt in ['pie', 'nopie']:
                #for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                for opt in ['ofast']:
                    #for lopt in ['bfd', 'gold']:
                    for lopt in ['bfd']:
                        sub_dir = '%s/%s/%s/%s/%s-%s'%(package, arch, comp, popt, opt, lopt)
                        input_dir = '%s/%s'%(input_root, sub_dir)
                        for target in glob.glob('%s/reloc/*'%(input_dir)):

                            filename = os.path.basename(target)
                            out_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                            ret.append(BuildConf(target, input_dir, out_dir, arch, popt))
    return ret

def job(conf, bPreprocessing=True):
    reassessor = Reassessor(conf.target, '%s/assem'%(conf.input_path), conf.output_path)
    if bPreprocessing:
        download()
        reassessor.preprocessing()
    else:
        if os.path.exists(conf.output_path+'/reassem/ramblr.s'):
            reassessor.ramblr_output        = conf.output_path + '/reassem/ramblr.s'
        if os.path.exists(conf.output_path+'/reassem/retrowrite.s'):
            reassessor.retrowrite_output    = conf.output_path + '/reassem/retrowrite.s'
        if os.path.exists(conf.output_path+'/reassem/ddisasm.s'):
            reassessor.ddisasm_output       = conf.output_path + '/reassem/ddisasm.s'

    reassessor.run_normalizer()
    reassessor.run_differ()

def docker_job(conf, bPreprocessing=True):
    cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor sh -c "/Reassessor/reassesor.py /input/reloc/%s /input/assem /output/ --reloc /input/reloc/%s'%(conf.input_path, conf.output_path, os.path.basename(conf.target), os.path.basename(conf.target))
    if bPreprocessing:
        download()
    else:
        if os.path.exists(conf.output_path+'/reassem/ramblr.s'):
            cmd += ' --ramblr /output/reassem/ramblr.s'
        if os.path.exists(conf.output_path+'/reassem/retrowrite.s'):
            cmd += ' --retrowrite /output/reassem/retrowrite.s'
        if os.path.exists(conf.output_path+'/reassem/ddisasm.s'):
            cmd += ' --ddisasm /output/reassem/ddisas.s'
    cmd += '"'
    os.system(cmd)


def run(package, core=1, bPreprocessing=True, bDocker=False):
    if package not in ['coreutils-8.30', 'binutils-2.31.1']:
        return False
    input_path = './downloads'
    output_path = './output'
    #input_path = './downloads/%s'%(package)
    #output_path = './output/%s'%(package)
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
    args = parser.parse_args()

    if args.package:
        run(args.package, args.core, args.preprocessing, args.docker)
    else:
        for package in ['coreutils-8.30', 'binutils-2.31.1']:
            run(package, args.core, args.preprocessing, args.docker)


