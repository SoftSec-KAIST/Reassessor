from elftools.elf.elffile import ELFFile
import os

class Reassessor:
    def __init__(self, target, assem_dir, output_dir):
        f = open(target, 'rb')
        self.elffile = ELFFile(f)
        self.target = target
        self.assem_dir  = assem_dir
        self.output_dir = output_dir
        self.arch   = self.check_arch()
        self.pie    = self.check_pie()

    def check_arch(self):
        if self.elffile['e_machine'] in ('EM_386', 'EM_486'):
            return 'x86'
        elif self.elffile['e_machine'] in ('EM_X86_64'):
            return 'x64'
        assert False, 'Unknown architecture'

    def check_pie(self):
        if self.elffile.header['e_type'] in ('ET_DYN'):
            return 'pie'
        if self.elffile.header['e_type'] in ('ET_EXEC'):
            return 'nopie'
        assert False, 'Unknown file type'

    def preprocessing(self):
        #copy bin & strip binary
        self.base_name = os.path.basename(self.target)
        self.binary = '%s/bin/%s'%(self.output_dir, self.base_name)
        self.strip  = '%s/strip/%s'%(self.output_dir, self.base_name)

        os.system('mkdir -p %s/bin'%(self.output_dir))
        os.system('mkdir -p %s/strip'%(self.output_dir))
        os.system('./preprocessing/strip.sh %s %s %s'%(self.target, self.binary, self.strip))

        os.system('mkdir -p %s/reassem'%(self.output_dir))
        #create reassembly files
        self.retrowrite_output = self.run_retrowrite()

        self.ramblr_output = self.run_ramblr()

        self.ddisasm_output = self.run_ddisasm()

    def run_cmd(self, cmd, output=''):
        print(cmd)
        os.system(cmd)
        if output and os.path.exists(output):
            return output
        return ''

    def run_retrowrite(self):
        if self.arch != 'x64' or self.pie != 'pie':
            return ''
        reassem_output = '%s/reassem/retrowrite.s'%(self.output_dir)
        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/retrowrite:613562 sh -c "/root/retrowrite.sh /input/%s /output/reassem/retrowrite.s"'%(os.path.dirname(self.binary), self.output_dir, self.base_name)
        return self.run_cmd(cmd, reassem_output)

    def run_ramblr(self):
        if self.pie != 'nopie':
            return ''
        reassem_output = '%s/reassem/ramblr.s'%(self.output_dir)
        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/ramblr:64d1049 sh -c "/root/ramblr.sh /input/%s /output/reassem/ramblr"'%(os.path.dirname(self.binary), self.output_dir, self.base_name)
        return self.run_cmd(cmd, reassem_output)


    def run_ddisasm(self):
        reassem_output = '%s/reassem/ddisasm.s'%(self.output_dir)
        cmd = 'sudo docker run --rm -v %s:/input -v %s:/output reassessor/ddisasm:1.5.3 sh -c "ddisasm --debug /input/%s --asm /output/reassem/ddisasm.s"'%(os.path.dirname(self.binary), self.output_dir, self.base_name)
        return self.run_cmd(cmd, reassem_output)


    def run_normalizer(self):
        os.system('mkdir -p %s/norm_db'%(self.output_dir))
        norm = '%s/norm_db/gt.db'%(self.output_dir)
        cmd = 'python3 -m normalizer.gt %s %s %s --reloc %s'%(self.binary, self.assem_dir, norm, self.target)
        self.gt_norm = self.run_cmd(cmd, norm)
        self.retrowrite_norm = ''
        self.ramblr_norm = ''
        self.ddisasm_norm = ''

        if self.retrowrite_output:
            norm = '%s/norm_db/retrowrite.db'%(self.output_dir)
            cmd = 'python3 -m normalizer.retro %s %s %s'%(self.binary, self.retrowrite_output, norm)
            self.retrowrite_norm = self.run_cmd(cmd, norm)
        if self.ramblr_output:
            norm = '%s/norm_db/ramblr.db'%(self.output_dir)
            cmd = 'python3 -m normalizer.ramblr %s %s %s'%(self.binary, self.ramblr_output, norm)
            self.ramblr_norm = self.run_cmd(cmd, norm)
        if self.ddisasm_output:
            norm = '%s/norm_db/ddisasm.db'%(self.output_dir)
            cmd = 'python3 -m normalizer.ddisasm %s %s %s'%(self.binary, self.ddisasm_output, norm)
            self.ddisasm_norm = self.run_cmd(cmd, norm)

    def run_differ(self):
        cmd = 'python3 -m differ.diff %s %s %s'%(self.binary, self.gt_norm, self.output_dir)
        if self.retrowrite_norm:
            cmd1 = '%s/errors/retro --retro %s'%(cmd, self.retrowrite_norm)
            self.run_cmd(cmd1)
        if self.ramblr_norm:
            cmd2 = '%s/errors/ramblr --ramblr %s'%(cmd, self.ramblr_norm)
            self.run_cmd(cmd2)
        if self.ddisasm_norm:
            cmd3 = '%s/errors/ddisasm --ddisasm %s'%(cmd, self.ddisasm_norm)
            self.run_cmd(cmd3)

import argparse
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='manager')
    parser.add_argument('target', type=str, help='Target Binary')
    parser.add_argument('assem_dir', type=str, help='Assembly Directory')
    parser.add_argument('output_dir', type=str, help='output_dir')
    args = parser.parse_args()

    reassessor = Reassessor(args.target, args.assem_dir, args.output_dir)
    reassessor.preprocessing()
    reassessor.run_normalizer()
    reassessor.run_differ()

