from collections import namedtuple
import os
import pickle
import glob
import multiprocessing

#from differ.ereport import ERec

ERec = namedtuple('ERec', ['record', 'gt'])

BuildConf = namedtuple('BuildConf', ['bin', 'reloc', 'gt_asm', 'strip', 'gt_out', 'retro_asm', 'retro_out', 'ddisasm_asm', 'ddisasm_out', 'ramblr_asm', 'ramblr_out', 'result'])

#black_list = ['Ghost_In_The_CGC', 'Trust_Platform_Module', 'Hug_Game', 'FSK_Messaging_Service', 'Water_Treatment_Facility_Simulator', 'Lazybox', 'ECM_TCM_Simulator', 'Network_File_System', 'Scrum_Database', 'PRU', 'Virtual_Machine', 'LAN_Simulator', 'Thermal_Controller_v2', 'WhackJack', 'Personal_Fitness_Manager', 'Shortest_Path_Tree_Calculator', 'Corinth', 'Monster_Game', 'Network_File_System_v3', '3D_Image_Toolkit', 'Query_Calculator', 'Flash_File_System', 'Filesystem_Command_Shell', 'Thermal_Controller_v3', 'Recipe_and_Pantry_Manager', 'FaceMag', 'Facilities_Access_Control_System', 'REMATCH_1--Hat_Trick--Morris_Worm', 'REMATCH_3--Address_Resolution_Service--SQL_Slammer', 'REMATCH_4--CGCRPC_Server--MS08-067', 'REMATCH_5--File_Explorer--LNK_Bug', 'REMATCH_6--Secure_Server--Heartbleed', 'REMATCH_2--Mail_Server--Crackaddr', 'Multi_User_Calendar', 'Secure_Compression', 'OTPSim', 'Grit', 'Barcoder', 'Childs_Game', 'Pattern_Finder', 'vFilter', 'Messaging', 'Venture_Calculator', 'Space_Attackers', 'Fortress', 'Pac_for_Edges', 'XStore', 'Sorter', 'FailAV', 'BIRC', 'ShoutCTF', 'CML', 'Neural_House', 'Finicky_File_Folder', 'Mount_Filemore', 'One_Amp', 'LazyCalc', 'Blubber', 'Gridder', 'Azurad', 'Terrible_Ticket_Tracker', 'String_Info_Calculator', 'Checkmate', 'Stock_Exchange_Simulator', 'CLOUDCOMPUTE', 'Matchmaker', 'CAT', 'Overflow_Parking', 'One_Vote', 'PTaaS', 'COLLIDEOSCOPE', 'EternalPass', 'Snail_Mail', 'Rejistar', 'On_Sale', 'Dungeon_Master', 'Game_Night', 'OUTLAW', 'Order_Up', 'Multi_Arena_Pursuit_Simulator', 'SBTP', 'A_Game_of_Chance']

#black_list = ['444.namd', '447.dealII', '450.soplex', '453.povray', '471.omnetpp', '473.astar', '483.xalancbmk']
#white_list = ['444.namd', '447.dealII', '450.soplex', '453.povray', '471.omnetpp', '473.astar', '483.xalancbmk']
black_list = ['416.gamess', '434.zeusmp']
#white_list = ['416.gamess', '434.zeusmp']

def job(conf, reset=False):
    #diff_option = '--error'
    #diff_option = '--disasm'
    diff_option = ''
    #create_gt(conf, reset)

    #if create_retro(conf, reset):
    #    diff_retro(conf, diff_option, reset)

    #if create_ddisasm(conf, reset):
    #    diff_ddisasm(conf, diff_option, reset)

    #if create_ramblr(conf, reset):
    #    diff_ramblr(conf, diff_option, reset)
    #diff_retro(conf, diff_option, reset)
    #diff_ddisasm(conf, diff_option, reset)
    #diff_ramblr(conf, diff_option, reset)

class RecCounter:
    def __init__(self, tool):
        self.tool = tool
        self.board = list()
        for i in range(9):
            self.board.append({'tp':0, 'fp':0, 'fn':0})

        self.no_error = 0

        self.error = 0
        self.success = 0
        self.tot_gt = 0

        self.disasm_tp = 0
        self.disasm_fp = 0
        self.disasm_fn = 0

    def add(self, pickle_path, disasm_path):
        if not os.path.exists(pickle_path):
            #print(pickle_path)
            self.error += 1
            return

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
            if 1000 < int(disasm_fn) + int(disasm_fp) :
                print('> %-110s %7s %7s'%(disasm_path, disasm_fn, disasm_fp))


    def report(self):
        print('        %8s %8s %8s'%('TP', 'FP', 'FN'))
        for stype in range(1, 9):
            print('Type %d: %8d %8d %8d'%(stype, self.board[stype]['tp'] , self.board[stype]['fp'] , self.board[stype]['fn']))

        print('Total : %8d'%(self.tot_gt))



class WorkBin:
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result3', retro='/data3/1_reassessor/new_retro', ddisasm='/data3/1_reassessor/debug_dd2', ramblr='/data3/1_reassessor/new_ramblr'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result4', retro='/data3/1_reassessor/new_retro_fix', ddisasm='/data3/1_reassessor/debug_dd2', ramblr='/data3/1_reassessor/new_ramblr'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result5', retro='/data3/1_reassessor/new_retro_fix', ddisasm='/data3/1_reassessor/debug_dd2', ramblr='/data3/1_reassessor/new_ramblr_origin'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result6', retro='/data3/1_reassessor/new_retro_fix2', ddisasm='/data3/1_reassessor/debug_dd3', ramblr='/data3/1_reassessor/new_ramblr2'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result7', retro='/data3/1_reassessor/new_retro_fix', ddisasm='/data3/1_reassessor/debug_dd2', ramblr='/data3/1_reassessor/new_ramblr'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result7', retro='/data3/1_reassessor/new_retro_fix3', ddisasm='/data3/1_reassessor/debug_dd3', ramblr='/data3/1_reassessor/new_rmblr2'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result7', retro='/data3/1_reassessor/new_retro_fix3', ddisasm='/data3/1_reassessor/debug_dd3', ramblr='/data3/1_reassessor/new_rmblr2'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result8', retro='/data3/1_reassessor/new_retro_fix3', ddisasm='/data3/1_reassessor/debug_dd', ramblr='/data3/1_reassessor/new_rmblr2'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result7', retro='/data3/1_reassessor/new_retro_fix3', ddisasm='/data3/1_reassessor/debug_dd3', ramblr='/data3/1_reassessor/new_rmblr2'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/final_result', retro='/data3/1_reassessor/new_retro_fix3', ddisasm='/data3/1_reassessor/debug_dd3', ramblr='/data3/1_reassessor/new_rmblr2'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/new_result6', retro='/data3/1_reassessor/new_retro_fix2', ddisasm='/data3/1_reassessor/debug_dd3', ramblr='/data3/1_reassessor/new_ramblr2'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', out='/data3/1_reassessor/dataset/result', retro='/data3/1_reassessor/dataset/retrowrite', ddisasm='/data3/1_reassessor/dataset/ddisasm_debug', ramblr='/data3/1_reassessor/dataset/ramblr'):
    #def __init__(self, bench='/data3/1_reassessor/benchmark', norm_db='/data3/1_reassessor/norm_db', diff_db='/data3/1_reassessor/diff_db', retro='/data3/1_reassessor/dataset/retrowrite', ddisasm='/data3/1_reassessor/dataset/ddisasm_debug', ramblr='/data3/1_reassessor/dataset/ramblr'):
    def __init__(self, bench='/data3/1_reassessor/benchmark', norm_db='/data3/1_reassessor/new_result6', diff_db='/data3/1_reassessor/new_result6', retro='/data3/1_reassessor/dataset/retrowrite', ddisasm='/data3/1_reassessor/dataset/ddisasm_debug', ramblr='/data3/1_reassessor/dataset/ramblr'):
        self.bench = bench

        self.gt_norm_db = '/data3/1_reassessor/gt_db'
        #self.gt_norm_db = ''
        self.norm_db = norm_db
        self.diff_db = diff_db
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
            #exclude cgc final binaries
            if os.path.basename(binary) in black_list:
                continue
            '''
            if os.path.basename(binary) not in white_list:
                continue
            '''
            ret.append(self.gen_tuple(sub_dir, package, arch, pie_opt, binary))
        return ret

    def gen_tuple(self, sub_dir, package, arch, pie_opt, binary):
        filename = os.path.basename(binary)
        if pie_opt in ['nopie']:
            reloc = '%s/%s/reloc/%s'%(self.bench, sub_dir, filename)
        else:
            reloc = ''

        strip = '%s/stripbin/%s'%(self.bench, filename)

        if package in ['spec_cpu2006', 'cgc']:
            gt_asm = '%s/%s/asm/%s'%(self.bench, sub_dir, filename)
        else:
            gt_asm = '%s/%s/asm'%(self.bench, sub_dir)

        retro_asm = self.get_retro(sub_dir, filename)
        ddisasm_asm = self.get_ddisasm(sub_dir, filename)
        ramblr_asm = self.get_ramblr(sub_dir, filename)

        if self.gt_norm_db:
            gt_norm_db = '%s/%s/%s/pickle/gt2.dat'%(self.gt_norm_db, sub_dir, filename)
        else:
            gt_norm_db = '%s/%s/%s/pickle/gt2.dat'%(self.norm_db, sub_dir, filename)

        retro_norm_db = '%s/%s/%s/pickle/retro.dat'%(self.norm_db, sub_dir, filename)
        ddisasm_norm_db = '%s/%s/%s/pickle/ddisasm2.dat'%(self.norm_db, sub_dir, filename)
        ramblr_norm_db = '%s/%s/%s/pickle/ramblr.dat'%(self.norm_db, sub_dir, filename)

        if pie_opt in ['pie']:
            ramblr_asm = ''
            ramblr_norm_db = ''
        if pie_opt in ['nopie'] or arch in ['x86']:
            retro_asm = ''
            retro_norm_db = ''

        result = '%s/%s/%s'%(self.diff_db, sub_dir, filename)

        return BuildConf(binary, reloc, gt_asm, strip, gt_norm_db, retro_asm, retro_norm_db, ddisasm_asm, ddisasm_norm_db, ramblr_asm, ramblr_norm_db, result)


def diff_retro(conf, option, reset):
    if not conf.retro_asm or not os.path.exists(conf.retro_asm):
        return
    if conf.retro_out:
        diff('retro', conf.bin, conf.gt_out, conf.retro_out, conf.result, option, reset)

def diff_ddisasm(conf, option, reset):
    if not conf.ddisasm_asm or not os.path.exists(conf.ddisasm_asm):
        return
    if conf.ddisasm_out:
        diff('ddisasm', conf.bin, conf.gt_out, conf.ddisasm_out, conf.result, option, reset)

def diff_ramblr(conf, option, reset):
    if not conf.ramblr_asm or not os.path.exists(conf.ramblr_asm):
        return
    if conf.ramblr_out:
        diff('ramblr', conf.bin, conf.gt_out, conf.ramblr_out, conf.result, option, reset)


def diff(tool_name, binfile, gt_out, tool_out, result, option, reset):
    if os.path.getsize(tool_out) == 0:
        return

    if tool_name in ['retro']:
        pickle_path = result + '/error_pickle/retro_sym'
    else:
        pickle_path = result + '/error_pickle/' + tool_name

    # create new pickle
    if not reset and os.path.exists(pickle_path):
        return

    os.system('mkdir -p %s'%(os.path.dirname(result)))
    #print('python3 -m differ.diff %s %s %s --%s %s %s'%(binfile, gt_out, result, tool_name, tool_out, option))
    os.system('python3 -m differ.diff %s %s %s --%s %s %s'%(binfile, gt_out, result, tool_name, tool_out, option))



def create_gt(conf, reset):
    return create_db('gt',     conf.bin, conf.gt_asm, conf.gt_out, reset, conf.reloc)

def create_retro(conf, reset):
    if conf.retro_asm:
        return create_db('retro',  conf.bin, conf.retro_asm, conf.retro_out, reset)
    return False

def create_ddisasm(conf, reset):
    if conf.ddisasm_asm:
        return create_db('ddisasm',  conf.bin, conf.ddisasm_asm, conf.ddisasm_out, reset)
    return False

def create_ramblr(conf, reset):
    if conf.ramblr_asm:
        return create_db('ramblr',  conf.bin, conf.ramblr_asm, conf.ramblr_out, reset)
    return False

def create_db(tool_name, bin_file, assem, output, reset=False, reloc=''):
    if not reset and os.path.exists(output):
        return False
    option = ''
    if tool_name != 'gt':
        #print(assem)
        if not os.path.exists(assem):
            return False
        if os.path.getsize(assem) == 0:
            return False
    elif tool_name == 'gt' and reloc:
        option = '--reloc %s'%(reloc)

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
        for pack in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006']:
            for arch in ['x86', 'x64']:
                for comp in ['clang', 'gcc']:
                    for popt in ['pie', 'nopie']:
                        #for opt in ['ofast', 'os', 'o3', 'o2', 'o1', 'o0']:
                        for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                            for lopt in ['bfd', 'gold']:

                                sub_dir = '%s/%s/%s/%s/%s-%s'%(pack, arch, comp, popt, opt, lopt)
                                ret.extend(gen.get_tuple(sub_dir, pack, arch, popt))
        return ret

    def single_run(self, target):
        path = os.path.dirname(target)
        filename = os.path.basename(target)

        sub_dir = '/'.join(path.split('/')[-6:-1])
        (package, arch, comp, pie_opt, lopt) = sub_dir.split('/')
        assert package in ['coreutils-8.30', 'binutils-2.31.1', 'spec_cpu2006', 'cgc'], 'invalid package'

        gen = WorkBin()
        conf = gen.gen_tuple(sub_dir, package, arch, pie_opt, target)
        job(conf, reset=True)

    def run(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(job, (self.conf_list))
        else:
            for conf in self.conf_list:
                job(conf)

    def merge(self, tool, white_list):
        counter = RecCounter(tool)
        '''
        if tool != 'ramblr':
            return counter

        for arch in ['x86']:
            for opt in ['o0', 'o1', 'o2', 'o3', 'os', 'ofast']:
                counterx = RecCounter(tool)
                sub_dir = '%s/clang/nopie/%s-bfd'%(arch, opt)
                print(sub_dir)
                for conf in self.conf_list:
                    if sub_dir not in conf.ramblr_asm:
                        continue

                    pickle = conf.result+'/error_pickle/' + tool
                    disasm = conf.result+'/disasm_diff/' + tool
                    counterx.add(pickle, disasm)

                counterx.report()

                #print('%7s  # of TPs  %12d  '%('',counterx.disasm_tp))
                #print('%7s  # of FPs  %12d  '%('Disasm',counterx.disasm_fp))
                #print('%7s  # of FNs  %12d  '%('',counterx.disasm_fn))
        '''
        if white_list:
            f = open(white_list)
            my_list = [line for line in f.read().split()]


        for conf in self.conf_list:

            if white_list:
                if conf.ddisasm_asm not in my_list:
                    continue

            if tool == 'ramblr' and not conf.ramblr_asm:
                continue
            if tool == 'retro_sym' and not conf.retro_asm:
                continue


            pickle = conf.result+'/error_pickle/' + tool
            disasm = conf.result+'/disasm_diff/' + tool
            counter.add(pickle, disasm)

        #print('no error (%s): %d'%(tool, counter.no_error))
        #counter.report()
        return counter

    def report(self, white_list=None):
        #---------------------------------------------

        #print('> %-110s %7s %7s'%('', 'FN'.center(7), 'FP'.center(7)))
        retro = self.merge('retro_sym', white_list)
        ddisasm = self.merge('ddisasm', white_list)
        ramblr = self.merge('ramblr', white_list)

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
    parser.add_argument('--list', type=str)
    args = parser.parse_args()

    mgr = Manager(args.core)

    if args.target:
        mgr.single_run(args.target)
    elif args.list:
        mgr.report(args.list)
    else:
        mgr.run()
        mgr.report()

