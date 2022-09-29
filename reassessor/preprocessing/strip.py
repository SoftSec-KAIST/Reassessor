import os

useless_sections = ['.rel.init', '.rel.text', '.rel.fini', '.rel.rodata', '.rel.eh_frame',
                    '.rel.init_array', '.rel.fini_array', '.rel.debug_aranges', '.rel.debug_info',
                    '.rel.debug_loc', '.rel.debug_ranges',  '.rel.data.rel.ro', '.rel.data',
                    '.rel.debug_line', '.data.rel.rodata',  '.rela.init', '.rela.text',
                    '.rela.fini', '.rela.rodata', '.rela.eh_frame', '.rela.init_array',
                    '.rela.fini_array', '.rela.debug_aranges', '.rela.debug_info', '.rela.debug_loc',
                    '.rela.debug_ranges',  '.rela.data.rel.ro', '.rela.data', '.rela.debug_line',
                    '.data.rela.rodata',  '.rand']

def remove_useless_sections(binary):
    for section in useless_sections:
        os.system('objcopy --remove-section %s %s'%(section, binary))



def copy_and_strip(target, binary, strip_binary):
    os.system('cp %s %s'%(target, binary))
    remove_useless_sections(binary)
    os.system('cp %s %s'%(binary, strip_binary))
    os.system('strip %s'%(strip_binary))


import argparse
if __name__ == '__main__':
    parser = argparse.ARgumentParser(description='strip')
    parser.add_argument('target', type=str, help='Target Binary')
    parser.add_argument('binary', type=str, help='Binary path')
    parser.add_argument('strip_binary', type=str, help='strip binary path')

    args = parser.parse_args()

    copy_and_strip(args.target, args.binary, args.strip_binary)
