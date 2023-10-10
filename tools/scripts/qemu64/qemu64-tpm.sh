#!/bin/bash


# Usage:

# For DEBUG_STAGE1 without waiting for GDB: ./qemu64-tpm.sh -d DEBUG_STAGE1 -w
# For DEBUG_STAGE2 without waiting for GDB: ./qemu64-tpm.sh -w
# For DEBUG_STAGE1 with waiting for GDB (default): ./qemu64-tpm.sh -d DEBUG_STAGE1
# For DEBUG_STAGE2 with waiting for GDB (default): ./qemu64-tpm.sh


# To DEBUG_STAGE1
# $ gdb stage1/loader_stage1.elf
# target remote :1234
# b start
# c

# To DEBUG_STAGE2
# $ gdb wolfboot.elf
# target remote :1234
# b main
# c


## TPM emulator:
# https://github.com/stefanberger/swtpm

# Default values
DEBUG_STAGE="DEBUG_STAGE2"
WAIT_FOR_GDB=true

# Parse command line options
while getopts "d:w" opt; do
    case "$opt" in
        d)
            DEBUG_STAGE="$OPTARG"
            ;;
        w)
            WAIT_FOR_GDB=false
            ;;
        *)
            echo "Usage: $0 [-d DEBUG_STAGE1 | DEBUG_STAGE2] [-w]"
            exit 1
            ;;
    esac
done

if (test -z $OVMF_PATH); then
    if (test -f /usr/share/edk2-ovmf/x64/OVMF.fd); then
        OVMF_PATH=/usr/share/edk2-ovmf/x64
    elif (test -f /usr/share/qemu/OVMF.fd); then
        OVMF_PATH=/usr/share/qemu
    else
        OVMF_PATH=/
    fi
fi

QEMU_TPM_OPTIONS=" \
    -chardev socket,id=chrtpm,path=/tmp/swtpm/swtpm-sock \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0"

QEMU_OPTIONS=" \
    -m 1G -machine q35 -serial mon:stdio -nographic \
    -pflash wolfboot_stage1.bin -drive id=mydisk,format=raw,file=app.bin,if=none \
    -device ide-hd,drive=mydisk"

# If waiting for GDB is true, append options to QEMU_OPTIONS
if [ "$WAIT_FOR_GDB" = true ]; then
    QEMU_OPTIONS="${QEMU_OPTIONS} -S -s"
fi

if [ "$DEBUG_STAGE" = "DEBUG_STAGE1" ]; then
    QEMU=qemu-system-i386
else
    QEMU=qemu-system-x86_64
fi

killall swtpm
sleep 1
echo TPM Emulation ON
mkdir -p /tmp/swtpm
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm \
    --ctrl type=unixio,path=/tmp/swtpm/swtpm-sock --log level=20 &
sleep .5
echo Running QEMU...

echo "$QEMU $QEMU_OPTIONS $QEMU_TPM_OPTIONS"
$QEMU $QEMU_OPTIONS $QEMU_TPM_OPTIONS
