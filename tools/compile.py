
import os
import subprocess
import sys

def compile(conf):
    cmd_list = compile_cmd(conf)
    if not cmd_list:
        return

    os.system(cmd_list[0])
    for cmd in cmd_list[1:]:

        try:
            subprocess.check_output(cmd.split(), stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print(cmd)
            print('exit code: {}'.format(e.returncode))
            #print('stdout: {}'.format(e.output.decode(sys.getfilesystemencoding())))
            #print('stderr: {}'.format(e.stderr.decode(sys.getfilesystemencoding())))

            logfile = '%s/%s/%s/log/%s.log'%(conf.tool_path, conf.sub_dir, conf.tool_name, conf.filename)
            print(logfile)

            os.system('mkdir -p %s'%(os.path.dirname(logfile)))
            with open(logfile, 'w') as fp:
                fp.write(e.stderr.decode(sys.getfilesystemencoding()))


def compile_cmd(conf):
    bfile = '%s/%s/bin/%s'% (conf.bench, conf.sub_dir, conf.filename)
    rfile = '%s/%s/%s/%s.s'%(conf.tool_path, conf.sub_dir, conf.tool_name, conf.filename)

    if not os.path.exists(rfile):
        return []

    output = '%s/%s/%s/bin/%s'%(conf.tool_path, conf.sub_dir, conf.tool_name, conf.filename)
    if conf.filename.split('.')[0] in ['444','447','450','453','471','473','483']:
        if conf.compiler in ['gcc']:
            compiler = 'g++'
        elif conf.compiler in ['clang']:
            compiler = 'clang++-12'
    elif conf.filename.split('.')[0] in ['410','416','434','435','436','437','454','459','465','481']:
        compiler = 'gfortran'
    else:
        if conf.compiler in ['gcc']:
            compiler = 'gcc'
        elif conf.compiler in ['clang']:
            compiler = 'clang-12'

    res = os.popen('ldd %s'%(bfile)).read()
    libs = ''
    for line in res.split('\n')[1:]:
        if not line or 'not found' in line:
            continue
        if '=>' in line:
            lib = line.split()[2]
        else:
            lib = line.split()[0]
        libs += lib + ' '

    if conf.pie in ['pie']:
        popt = '-pie -fpie'
    else:
        popt = '-no-pie -fno-pie'

    if conf.arch in ['x86']:
        arch = '-m32'
    else:
        arch = ''

    cmd = []
    cmd.append('mkdir -p %s'%(os.path.dirname(output)))
    cmd.append('%s %s -o %s %s %s -ldl %s'%(compiler, rfile, output, popt, arch, libs))

    return cmd


