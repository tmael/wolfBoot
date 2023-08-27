#!/bin/bash

FILES=(
hal/x86_fsp_qemu.c
src/string.c
src/image.c
src/libwolfboot.c
src/keystore.c
src/loader.c
hal/x86_uart.c
src/boot_x86_fsp_payload.c
src/x86/common.c
src/x86/hob.c
src/pci.c
src/x86/ahci.c
src/x86/ata.c
src/x86/gpt.c
src/x86/mptable.c
src/xmalloc.c
lib/wolfTPM/src/tpm2.c
lib/wolfTPM/src/tpm2_packet.c
lib/wolfTPM/src/tpm2_tis.c
lib/wolfTPM/src/tpm2_wrap.c
lib/wolfTPM/src/tpm2_param_enc.c
lib/wolfTPM/hal/tpm_io_mmio.c
src/x86/linux_loader.c
lib/wolfssl/wolfcrypt/src/sha256.c
lib/wolfssl/wolfcrypt/src/logging.c
lib/wolfssl/wolfcrypt/src/random.c
lib/wolfssl/wolfcrypt/src/sp_int.c
lib/wolfssl/wolfcrypt/src/sp_c32.c
lib/wolfssl/wolfcrypt/src/ecc.c
lib/wolfssl/wolfcrypt/src/memory.c
lib/wolfssl/wolfcrypt/src/wc_port.c
lib/wolfssl/wolfcrypt/src/wolfmath.c
lib/wolfssl/wolfcrypt/src/hash.c
lib/wolfssl/wolfcrypt/src/aes.c
lib/wolfssl/wolfcrypt/src/hmac.c
lib/wolfssl/wolfcrypt/src/sha512.c
src/update_disk.c
)

prepend_text() {
    for file in "${FILES[@]}"; do
        echo "Prepending text to $file"
        sed -i '1s;^;#ifdef USER_SETTINGS_TRIMMING_DO178\n#include <user_settings_do178.h>\n#endif\n;' "$file"
    done
}

remove_text() {
    for file in "${FILES[@]}"; do
        echo "Removing text from $file"
        sed -i '/^#ifdef USER_SETTINGS_TRIMMING_DO178$/,/^#endif$/d' "$file"
    done
}

# Command line option parsing
while getopts ":ar" opt; do
    case $opt in
        a)
            prepend_text
            ;;
        r)
            remove_text
            ;;
        *)
            echo "Usage: $0 [-a (add) | -r (remove)]"
            exit 1
            ;;
    esac
done

if [ $OPTIND -eq 1 ]; then
    echo "Usage: $0 [-a (add) | -r (remove)]"
    exit 1
fi
