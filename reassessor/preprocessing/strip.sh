#!/bin/bash

function remove_useless_sections
{
    #remove unneccessary sections
    objcopy --remove-section .rel.init $1
    objcopy --remove-section .rel.text $1
    objcopy --remove-section .rel.fini $1
    objcopy --remove-section .rel.rodata $1
    objcopy --remove-section .rel.eh_frame $1
    objcopy --remove-section .rel.init_array $1
    objcopy --remove-section .rel.fini_array $1
    objcopy --remove-section .rel.debug_aranges $1
    objcopy --remove-section .rel.debug_info $1
    objcopy --remove-section .rel.debug_loc $1
    objcopy --remove-section .rel.debug_ranges $1

    objcopy --remove-section .rel.data.rel.ro $1
    objcopy --remove-section .rel.data $1
    objcopy --remove-section .rel.debug_line $1
    objcopy --remove-section .data.rel.rodata $1

    objcopy --remove-section .rela.init $1
    objcopy --remove-section .rela.text $1
    objcopy --remove-section .rela.fini $1
    objcopy --remove-section .rela.rodata $1
    objcopy --remove-section .rela.eh_frame $1
    objcopy --remove-section .rela.init_array $1
    objcopy --remove-section .rela.fini_array $1
    objcopy --remove-section .rela.debug_aranges $1
    objcopy --remove-section .rela.debug_info $1
    objcopy --remove-section .rela.debug_loc $1
    objcopy --remove-section .rela.debug_ranges $1

    objcopy --remove-section .rela.data.rel.ro $1
    objcopy --remove-section .rela.data $1
    objcopy --remove-section .rela.debug_line $1
    objcopy --remove-section .data.rela.rodata $1

    objcopy --remove-section .rand $1

}

function copy_and_strip
{
    target=$1
    binary=$2
    strip_binary=$3

    echo "copy binary file $binary"
    cp $target $binary
    remove_useless_sections $binary

    echo "strip binary file $strip_binary"
    cp $binary $strip_binary
    strip $strip_binary
}

if (( $# != 3 ))
then
        printf "USAGE: $0 [target binary] [binary path] [strip binary path]\n"
        exit
fi

copy_and_strip $1 $2 $3

