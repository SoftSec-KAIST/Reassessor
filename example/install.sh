function my_strip
{
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

function copy_to_benchmark_folder
{
	out_folder=$1

    list_file=binutils-2.31.1_list.txt

	asm_dir=benchmark/$out_folder/asm
	bin_dir=benchmark/$out_folder/bin
	reloc_dir=benchmark/$out_folder/reloc
	stripbin_dir=benchmark/$out_folder/stripbin

	mkdir -p $asm_dir
	mkdir -p $bin_dir
	mkdir -p $reloc_dir
	mkdir -p $stripbin_dir

    find build -name '*.s' -exec cp --parents \{\} $asm_dir \;

    while IFS='' read -r line || [[ -n "$line" ]]; do
        name=$(echo $line | awk -F' ' '{print $1}')
        filename=$(basename "${line}")

        src=build/$out_folder/$name

        echo "cp $src 	$reloc_dir/$filename"
        cp $src 	$reloc_dir/$filename

        echo "cp $src 	$bin_dir/$filename"
        cp $src 	$bin_dir/$filename
        my_strip $bin_dir/$filename

        echo "cp $bin_dir/$filename 	$stripbin_dir/$filename"
        cp $bin_dir/$filename 	$stripbin_dir/$filename

    done < "$list_file"

}



function build_binutils
{
    PIEOPT=$1

    COMMON="-ggdb -save-temps=obj -fverbose-asm -Wl,--emit-relocs"
    OPT="-Os"
    LINKEROPT="-fuse-ld=bfd"
    GCC=/usr/bin/gcc
    ARCH=x64

    OPTSTR=`echo ${OPT:1} | tr '[:upper:]' '[:lower:]'`
    PIEOPTSTR=`echo $PIEOPT | tr '[:upper:]' '[:lower:]' | tr -d '-'`

    if [ "$PIEOPT" = "-pie" ]; then
        PIEFLAGS="-pie -fPIE"
    else
        PIEFLAGS="-no-pie -fno-PIC"
    fi

    out_dir=$ARCH\_gcc\_$PIEOPTSTR\_$OPTSTR
    mkdir -p build/$out_dir

    cd build/$out_dir

    ../../binutils-2.31.1/configure CFLAGS="$COMMON $OPT $PIEFLAGS $LINKEROPT" CC=$GCC
    make

    cd -

    copy_to_benchmark_folder $out_dir
}


#wget https://ftp.gnu.org/gnu/binutils/binutils-2.31.1.tar.xz
#tar -xvf binutils-2.31.1.tar.xz

build_binutils "-pie"
build_binutils "-no-pie"


