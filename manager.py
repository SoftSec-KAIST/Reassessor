from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

#from differ.ereport import ERec

ERec = namedtuple('ERec', ['record', 'gt'])

BuildConf = namedtuple('BuildConf', ['bin', 'reloc', 'gt_asm', 'strip', 'gt_out', 'retro_asm', 'retro_out', 'ddisasm_asm', 'ddisasm_out', 'ramblr_asm', 'ramblr_out', 'result'])

def job(conf, multi=True):
    diff_option = '--error'
    #diff_option = '--disasm'
    #create_gt(conf, multi)
    '''
    if create_retro(conf, multi):
        diff_retro(conf)

    if create_ddisasm(conf, multi):
        diff_ddisasm(conf)

    if create_ramblr(conf, multi):
        diff_ramblr(conf)
    '''
    diff_retro(conf, diff_option)
    diff_ddisasm(conf, diff_option)
    diff_ramblr(conf, diff_option)

class RecCounter:
    def __init__(self, tool):
        self.tool = tool
        self.board = list()
        for i in range(9):
            self.board.append({'tp':0, 'fp':0, 'fn':0})

        self.error = 0
        self.success = 0
        self.tot_gt = 0

        self.disasm_tp = 0
        self.disasm_fp = 0
        self.disasm_fn = 0

    def add(self, pickle_path, disasm_path):
        if not os.path.exists(pickle_path):
            self.error += 1
            return

        with open(pickle_path , 'rb') as fp:
            self.success += 1
            rec = pickle.load(fp)


            for stype in range(1, 9):
                self.board[stype]['tp'] += rec.record[stype].tp
                self.board[stype]['fp'] += rec.record[stype].fp.length()
                self.board[stype]['fn'] += rec.record[stype].fn.length()

            self.tot_gt += rec.gt

        with open(disasm_path) as fp:
            data = fp.readline()
            disasm_tp, disasm_fp, disasm_fn = data.strip().split(',')
            '''
            if '416.gamess' in disasm_path or '434.zeusmp' in disasm_path:
                return
            if '447.dealII' in disasm_path or '483.xalancbmk' in disasm_path:
                return
            if '436.cactusADM' in disasm_path or '454.calculix' in disasm_path or '403.gcc' in disasm_path or '435.gromacs' in disasm_path:
                return
            '''
            self.disasm_tp += int(disasm_tp)
            self.disasm_fp += int(disasm_fp)
            self.disasm_fn += int(disasm_fn)
            if 1000 < int(disasm_fn) + int(disasm_fp) :
                print('> %-110s %7s %7s'%(disasm_path, disasm_fn, disasm_fp))


    def report(self):
        print('        %8s %8s %8s'%('TP', 'FP', 'FN'))
        for stype in range(1, 9):
            print('Type %d: %8d %8d %8d'%(stype, self.board[stype]['tp'] , self.board[stype]['fp'] , self.board[stype]['fn']))

        print('Total : %8d'%(self.tot_gt))



class WorkBin:
    def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result2', retro='/data3/1_reassessor/benchmark', ddisasm='/data3/1_reassessor/debug_dd', ramblr='/data3/1_reassessor/ramblr'):
        self.bench = bench
        self.out = out
        self.retro = retro
        self.ddisasm = ddisasm
        self.ramblr = ramblr

    def get_retro(self, sub_dir, filename):
        return '%s/%s/retro_sym/%s.s'%(self.retro, sub_dir, filename)

    def get_ddisasm(self, sub_dir, filename):
        return '%s/%s/ddisasm/%s.s'%(self.ddisasm, sub_dir, filename)

    def get_ramblr(self, sub_dir, filename):
        return '%s/%s/ramblr/%s.s'%(self.ramblr, sub_dir, filename)

    def get_tuple(self, sub_dir, package, arch, pie_opt):
        ret = []
        #print('%s/%s/bin/*'%(self.bench, sub_dir))
        for binary in glob.glob('%s/%s/bin/*'%(self.bench, sub_dir)):
            ret.append(self.gen_tuple(sub_dir, package, arch, pie_opt, binary))
        return ret

    def gen_tuple(self, sub_dir, package, arch, pie_opt, binary):
        filename = os.path.basename(binary)
        if pie_opt in ['nopie']:
            reloc = '%s/%s/reloc/%s'%(self.bench, sub_dir, filename)
        else:
            reloc = ''

        strip = '%s/stripbin/%s'%(self.bench, filename)

        if package in ['spec_cpu2006']:
            gt_asm = '%s/%s/asm/%s'%(self.bench, sub_dir, filename)
        else:
            gt_asm = '%s/%s/asm'%(self.bench, sub_dir)

        retro_asm = self.get_retro(sub_dir, filename)
        ddisasm_asm = self.get_ddisasm(sub_dir, filename)
        ramblr_asm = self.get_ramblr(sub_dir, filename)


        gt_out = '%s/%s/%s/pickle/gt.dat'%(self.out, sub_dir, filename)
        retro_out = '%s/%s/%s/pickle/retro.dat'%(self.out, sub_dir, filename)
        ddisasm_out = '%s/%s/%s/pickle/ddisasm.dat'%(self.out, sub_dir, filename)
        ramblr_out = '%s/%s/%s/pickle/ramblr.dat'%(self.out, sub_dir, filename)

        if pie_opt in ['pie']:
            ramblr_asm = ''
            ramblr_out = ''
        if pie_opt in ['nopie'] or arch in ['x86']:
            retro_asm = ''
            retro_out = ''

        result = '%s/%s/%s'%(self.out, sub_dir, filename)

        return BuildConf(binary, reloc, gt_asm, strip, gt_out, retro_asm, retro_out, ddisasm_asm, ddisasm_out, ramblr_asm, ramblr_out, result)


def diff_retro(conf, option):
    if not conf.retro_asm or not os.path.exists(conf.retro_asm):
        return
    if conf.retro_out:
        diff('retro', conf.bin, conf.gt_out, conf.retro_out, conf.result, option)

def diff_ddisasm(conf, option):
    if not conf.ddisasm_asm or not os.path.exists(conf.ddisasm_asm):
        return
    if conf.ddisasm_out:
        diff('ddisasm', conf.bin, conf.gt_out, conf.ddisasm_out, conf.result, option)

def diff_ramblr(conf, option):
    if not conf.ramblr_asm or not os.path.exists(conf.ramblr_asm):
        return
    if conf.ramblr_out:
        diff('ramblr', conf.bin, conf.gt_out, conf.ramblr_out, conf.result, option)


def diff(tool_name, binfile, gt_out, tool_out, result, option):
    if not os.path.exists(tool_out):
        return
    if os.path.getsize(tool_out) == 0:
        return

    if tool_name in ['retro']:
        pickle_path = result + '/error_pickle/retro_sym'
    else:
        pickle_path = result + '/error_pickle/' + tool_name

    # create new pickle
    #if os.path.exists(pickle_path):
    #    return

    os.system('mkdir -p %s'%(os.path.dirname(result)))
    print('python3 -m differ.diff %s %s %s --%s %s %s'%(binfile, gt_out, result, tool_name, tool_out, option))
    os.system('python3 -m differ.diff %s %s %s --%s %s %s'%(binfile, gt_out, result, tool_name, tool_out, option))



def create_gt(conf, multi):
    return create_db('gt',     conf.bin, conf.gt_asm, conf.gt_out, multi, conf.reloc)

def create_retro(conf, multi):
    if conf.retro_asm:
        return create_db('retro',  conf.bin, conf.retro_asm, conf.retro_out, multi)
    return False

def create_ddisasm(conf, multi):
    if conf.ddisasm_asm:
        return create_db('ddisasm',  conf.bin, conf.ddisasm_asm, conf.ddisasm_out, multi)
    return False

def create_ramblr(conf, multi):
    if conf.ramblr_asm:
        return create_db('ramblr',  conf.bin, conf.ramblr_asm, conf.ramblr_out, multi)
    return False

def create_db(tool_name, bin_file, assem, output, multi=True, reloc=''):
    if os.path.exists(output):
        return False
    option = ''
    if tool_name != 'gt':
        if not os.path.exists(assem):
            return False
        if os.path.getsize(assem) == 0:
            return False
    elif tool_name == 'gt' and reloc:
        option = '--reloc %s'%(reloc)


    if not multi:
        print('python3 -m normalizer.%s %s %s %s %s'%(tool_name, bin_file, assem, output, option))

    os.system('mkdir -p %s'%(os.path.dirname(output)))
    os.system('python3 -m normalizer.%s %s %s %s %s'%(tool_name, bin_file, assem, output, option))
    return True

class Manager:
    def __init__(self, core):
        self.core = core
        if core > 1:
            self.multi = True
        else:
            self.multi = False

        self.conf_list = self.gen_option('/data2/benchmark')

    def gen_option(self, work_dir):
        ret = []
        gen = WorkBin()
        #for pack in ['spec_cpu2006']:
        #for pack in ['binutils-2.31.1']:
        #for pack in ['coreutils-8.30']:
        #for pack in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
        for pack in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            #for arch in ['x86']:
            for arch in ['x86', 'x64']:
                #for comp in ['gcc']:
                for comp in ['clang', 'gcc']:
                    for popt in ['pie', 'nopie']:
                        #for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                        #for opt in ['ofast']:
                        for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                            #for lopt in ['bfd']:
                            for lopt in ['bfd', 'gold']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                ret.extend(gen.get_tuple(sub_dir, pack, arch, popt))
        return ret

    def single_run(self, target):
        path = os.path.dirname(target)
        filename = os.path.basename(target)

        sub_dir = '/'.join(path.split('/')[-6:-1])
        (package, arch, comp, pie_opt, lopt) = sub_dir.split('/')
        assert package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006'], 'invalid package'

        gen = WorkBin()
        conf = gen.gen_tuple(sub_dir, package, arch, pie_opt, target)
        job(conf)

    def run(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(job, (self.conf_list))
        else:
            for conf in self.conf_list:
                job(conf, self.multi)

    def merge(self, tool):
        counter = RecCounter(tool)

        for conf in self.conf_list:
            if tool == 'ramblr' and not conf.ramblr_asm:
                continue
            if tool == 'retro_sym' and not conf.retro_asm:
                continue

            pickle = conf.result+'/error_pickle/' + tool
            disasm = conf.result+'/disasm_diff/' + tool
            counter.add(pickle, disasm)

        #counter.report()
        return counter

    def report(self):
        #---------------------------------------------

        print('> %-110s %7s %7s'%('', 'FN'.center(7), 'FP'.center(7)))
        retro = self.merge('retro_sym')
        ddisasm = self.merge('ddisasm')
        ramblr = self.merge('ramblr')

        print('                   %12s  %12s  %12s'%('Ramblr', 'RetroWrite', 'Ddisasm'))
        print('-' * 60 )
        print('# of Bins          %12d  %12d  %12d'%(ramblr.success, retro.success, ddisasm.success))
        print('# of Bins (FAIL)   %12d  %12d  %12d'%(ramblr.error, retro.error, ddisasm.error))
        print('# of Bins (TOTAL)  %12d  %12d  %12d'%(ramblr.success+ramblr.error, retro.success+retro.error, ddisasm.success+ddisasm.error))
        print('-' * 60 )

        for stype in range(1, 9):
            print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.board[stype]['tp'], retro.board[stype]['tp'], ddisasm.board[stype]['tp']))
            print('%7s  # of FPs  %12d  %12d  %12d'%('E%d'%(stype),ramblr.board[stype]['fp'], retro.board[stype]['fp'], ddisasm.board[stype]['fp']))
            print('%7s  # of FNs  %12d  %12d  %12d'%('',ramblr.board[stype]['fn'], retro.board[stype]['fn'], ddisasm.board[stype]['fn']))
            print('-' * 60 )

        print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.disasm_tp, retro.disasm_tp, ddisasm.disasm_tp))
        print('%7s  # of FPs  %12d  %12d  %12d'%('Disasm',ramblr.disasm_fp, retro.disasm_fp, ddisasm.disasm_fp))
        print('%7s  # of FNs  %12d  %12d  %12d'%('',ramblr.disasm_fn, retro.disasm_fn, ddisasm.disasm_fn))
        print('-' * 60 )

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1)
    parser.add_argument('--target', type=str)
    args = parser.parse_args()

    mgr = Manager(args.core)

    if args.target:
        mgr.single_run(args.target)
    else:
        mgr.run()
        mgr.report()

