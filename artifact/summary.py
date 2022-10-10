from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

black_list = []


class RecCounter:
    def __init__(self, tool):
        self.tool = tool
        self.board = list()
        for i in range(9):
            self.board.append({'tp':0, 'fp':0, 'fatal_fp':0, 'non-fatal_fp':0, 'fn':0})

        self.no_error = 0

        self.error = 0
        self.success = 0
        self.tot_gt = 0

        self.disasm_tp = 0
        self.disasm_fp = 0
        self.disasm_fn = 0
        self.exist = True

    def add(self, counter):
        if not counter.exist:
            self.error += 1
            return

        self.success += 1

        for stype in range(1, 9):
            self.board[stype]['tp'] += counter.board[stype]['tp']
            self.board[stype]['fp'] += counter.board[stype]['fp']
            self.board[stype]['fn'] += counter.board[stype]['fn']


        if counter.no_error:
            self.no_error += 1

        self.tot_gt += counter.tot_gt

        self.disasm_tp += counter.disasm_tp
        self.disasm_fp += counter.disasm_fp
        self.disasm_fn += counter.disasm_fn

    def set_data(self, pickle_path, disasm_path):
        if not os.path.exists(pickle_path):
            self.error += 1
            return

        #print(pickle_path)
        with open(pickle_path , 'rb') as fp:
            self.success += 1
            rec = pickle.load(fp)

            bError = False
            for stype in range(1, 9):
                self.board[stype]['tp'] += rec.record[stype].tp
                self.board[stype]['fp'] += rec.record[stype].fp.length()
                self.board[stype]['fn'] += rec.record[stype].fn.length()

                if rec.record[stype].fp.length():
                    bError = True
                if rec.record[stype].fn.length():
                    bError = True

            if not bError:
                self.no_error += 1

            self.tot_gt += rec.gt

        with open(disasm_path) as fp:
            data = fp.readline()
            disasm_tp, disasm_fp, disasm_fn = data.strip().split(',')
            self.disasm_tp += int(disasm_tp)
            self.disasm_fp += int(disasm_fp)
            self.disasm_fn += int(disasm_fn)

    def report(self):
        print('        %8s %8s %8s'%('TP', 'FP', 'FN'))
        for stype in range(1, 9):
            print('Type %d: %8d %8d(%8d) %8d'%(stype, self.board[stype]['tp'] , self.board[stype]['fp'] , self.board[stype]['fatal_fp'], self.board[stype]['fn']))

        print('Total : %8d'%(self.tot_gt))


def job(conf):
    counter = RecCounter(conf.tool)

    if not os.path.exists(conf.pickle):
        counter.exist = False
    else:
        counter.set_data(conf.pickle, conf.disasm)
    with open('res/%d'%(conf.idx), 'wb') as f:
        pickle.dump(counter, f)

BuildConf = namedtuple('BuildConf', ['tool', 'target', 'pickle', 'disasm', 'idx'])
global_no = 0

def gen_option(input_root, output_root):
    ret = []
    global global_no
    for package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
        for arch in ['x86', 'x64']:
            for comp in ['clang', 'gcc']:
                for popt in ['pie', 'nopie']:
                    for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                        for lopt in ['bfd', 'gold']:
                            sub_dir = '%s/%s/%s/%s/%s-%s'%(package, arch, comp, popt, opt, lopt)

                            for target in glob.glob('%s/%s/reloc/*'%(input_root, sub_dir)):

                                filename = os.path.basename(target)

                                output_dir = '%s/%s/%s'%(output_root, sub_dir, filename)

                                for tool in ['ramblr', 'retrowrite', 'ddisasm']:
                                    if tool == 'ramblr' and popt != 'nopie':
                                        continue
                                    if tool == 'retrowrite' and (popt != 'pie' or arch != 'x64'):
                                        continue

                                    pickle_file = '%s/errors/%s/sym_errors.dat'%(output_dir, tool)
                                    disasm = '%s/errors/%s/disasm_diff.txt'%(output_dir, tool)

                                    ret.append(BuildConf(tool, target, pickle_file, disasm, global_no))
                                    global_no += 1

    return ret





class Manager:
    def __init__(self, input_root='./dataset', output_root='./output'):
        self.config_list = gen_option(input_root, output_root)


    def run(self, core=1):
        if core and core > 1:
            p = multiprocessing.Pool(core)
            p.map(job, self.config_list)
        else:
            for conf in self.config_list:
                job(conf)




    def summary(self):
        res_dict = dict()
        res_dict['ramblr'] = RecCounter('ramblr')
        res_dict['retrowrite'] = RecCounter('retrowrite')
        res_dict['ddisasm'] = RecCounter('ddisasm')
        #---------------------------------------------
        global global_no
        for idx in range(global_no):
            with open('res/%d'%(idx), 'rb') as f:
                counter = pickle.load(f)
                res_dict[counter.tool].add(counter)

        self.report(res_dict['ramblr'], res_dict['retrowrite'], res_dict['ddisasm'])

    def report(self, ramblr, retro, ddisasm):
        print('-' * 60 )
        print('                   %12s  %12s  %12s'%('Ramblr', 'RetroWrite', 'Ddisasm'))
        print('-' * 60 )
        print('# of Bins          %12d  %12d  %12d'%(ramblr.success, retro.success, ddisasm.success))
        print('# of Bins (FAIL)   %12d  %12d  %12d'%(ramblr.error, retro.error, ddisasm.error))
        print('# of Bins (TOTAL)  %12d  %12d  %12d'%(ramblr.success+ramblr.error, retro.success+retro.error, ddisasm.success+ddisasm.error))
        print('-' * 60 )
        print('%7s  # of Succ %12d  %12d  %12d'%('',ramblr.no_error, retro.no_error, ddisasm.no_error))
        print('-' * 60 )

        for stype in range(1, 9):
            print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.board[stype]['tp'], retro.board[stype]['tp'], ddisasm.board[stype]['tp']))
            print('%7s  # of FNs  %12d  %12d  %12d'%('E%d'%(stype),ramblr.board[stype]['fn'], retro.board[stype]['fn'], ddisasm.board[stype]['fn']))
            print('%7s  # of FPs  %12d  %12d  %12d'%('',ramblr.board[stype]['fp'], retro.board[stype]['fp'], ddisasm.board[stype]['fp']))
            print('-' * 60 )

        print('%7s  # of TPs  %12d  %12d  %12d'%('',ramblr.disasm_tp, retro.disasm_tp, ddisasm.disasm_tp))
        print('%7s  # of FPs  %12d  %12d  %12d'%('Disasm',ramblr.disasm_fp, retro.disasm_fp, ddisasm.disasm_fp))
        print('%7s  # of FNs  %12d  %12d  %12d'%('',ramblr.disasm_fn, retro.disasm_fn, ddisasm.disasm_fn))
        print('-' * 60 )




import argparse
if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('--core', type=int, default=1, help='Number of cores to use')
    parser.add_argument('--skip', action='store_true')

    args = parser.parse_args()

    mgr = Manager(input_root='./dataset', output_root='./output')

    if not args.skip:
        os.system('mkdir -p ./res')
        if args.core:
            mgr.run(args.core)
        else:
            mgr.run()

    mgr.summary()





