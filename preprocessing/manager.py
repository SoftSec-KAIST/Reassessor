from abc import abstractmethod
from collections import namedtuple
import os
import multiprocessing
from compile import compile, compile_cmd
import subprocess, sys



REConf = namedtuple('REConf', ['bench', 'tool_name', 'tool_path', 'sub_dir', 'filename', 'arch', 'compiler', 'pie', 'lopt', 'reassem_cmd'])


def reassem(conf):
    #outpath = '%s/%s/%s/%s.s'%(conf.tool_path, conf.sub_dir, conf.tool_name, conf.filename)
    #if os.path.exists(outpath):
    #    return

    cmd_list = conf.reassem_cmd(conf)

    if not cmd_list:
        return

    print(cmd_list[0])
    os.system(cmd_list[0])

    for cmd in cmd_list[1:]:
        print(cmd)
        try:
            subprocess.check_output(cmd, stderr=subprocess.PIPE, shell=True)
        except subprocess.CalledProcessError as e:
            print(cmd)
            print('exit code: {}'.format(e.returncode))
            #print('stdout: {}'.format(e.output.decode(sys.getfilesystemencoding())))
            #print('stderr: {}'.format(e.stderr.decode(sys.getfilesystemencoding())))

            logfile = '%s/%s/log/%s/%s.log'%(conf.tool_path, conf.sub_dir, conf.tool_name, conf.filename)
            print(logfile)

            os.system('mkdir -p %s'%(os.path.dirname(logfile)))
            with open(logfile, 'w') as fp:
                fp.write(e.stderr.decode(sys.getfilesystemencoding()))


class Manager:
    def __init__(self, core, bench='/data3/1_reassessor/benchmark', tool_path='/data3/1_reassessor/new_ddisasm2', tool_name='ddisasm'):
        self.core = core
        if core > 1:
            self.multi = True
        else:
            self.multi = False
        self.bench = bench
        self.tool_path = tool_path
        self.conf_list = self.gen_option(self.bench, tool_name)

    @abstractmethod
    def gen_option(self, work_dir, tool_name):
        pass


    def run(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(reassem, (self.conf_list))
        else:
            for conf in self.conf_list:
                reassem(conf)

    def print_conf(self):
        for conf in self.conf_list:
            for cmd in conf.reassem_cmd(conf):
                print(cmd)

    def compile(self):
        if self.multi:
            p = multiprocessing.Pool(self.core)
            p.map(compile, (self.conf_list))
        else:
            for conf in self.conf_list:
                compile(conf)


    def print_compile_cmd(self):
        for conf in self.conf_list:
            for cmd in compile_cmd(conf):
                print(cmd)


