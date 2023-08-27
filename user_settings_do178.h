/* user_settings.h
 *
 * Custom configuration for wolfCrypt/wolfSSL.
 * Enabled via WOLFSSL_USER_SETTINGS.
 *
 *
 * Copyright (C) 2021 wolfSSL Inc.
 *
 * This file is part of wolfBoot.
 *
 * wolfBoot is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfBoot is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef H_USER_SETTINGS_
#define H_USER_SETTINGS_

#include <target.h>

/* System */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFCRYPT_ONLY
#define SIZEOF_LONG_LONG 8

#define CTYPE_USER /* don't let wolfCrypt types.h include ctype.h */
extern int toupper(int c);
extern int tolower(int c);
#define XTOUPPER(c)     toupper((c))
#define XTOLOWER(c)     tolower((c))

#ifdef USE_FAST_MATH
#   define WC_NO_HARDEN
#endif

/* ED25519 and SHA512 */
#ifdef WOLFBOOT_SIGN_ED25519
#   define HAVE_ED25519
#   define ED25519_SMALL
#   define NO_ED25519_SIGN
#   define NO_ED25519_EXPORT
#   define WOLFSSL_SHA512
#   define USE_SLOW_SHA512
#   define NO_RSA
#   define NO_ASN
#endif

/* ED448 */
#ifdef WOLFBOOT_SIGN_ED448
#   define HAVE_ED448
#   define HAVE_ED448_VERIFY
#   define ED448_SMALL
#   define NO_ED448_SIGN
#   define NO_ED448_EXPORT
#   define NO_RSA
#   define NO_ASN
#   define WOLFSSL_SHA3
#   define WOLFSSL_SHAKE256
#endif

/* ECC and SHA256 */
#if defined(WOLFBOOT_SIGN_ECC256) ||\
    defined(WOLFBOOT_SIGN_ECC384) ||\
    defined(WOLFBOOT_SIGN_ECC521)

#   define HAVE_ECC
#   define ECC_TIMING_RESISTANT
#   define ECC_USER_CURVES /* enables only 256-bit by default */

/* Kinetis LTC support */
#   ifdef FREESCALE_USE_LTC
#      define FREESCALE_COMMON
#      define FSL_HW_CRYPTO_MANUAL_SELECTION
#      define FREESCALE_LTC_ECC
#      define FREESCALE_LTC_TFM
#   endif

/* SP MATH */
#   if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
#       define WOLFSSL_SP
#       define WOLFSSL_SP_MATH
#       define WOLFSSL_SP_SMALL
#       define WOLFSSL_HAVE_SP_ECC
#   endif

/* ECC options disabled to reduce size */
#   define NO_ECC_SIGN
#   define NO_ECC_EXPORT
#   define NO_ECC_DHE

/* Curve */
#ifdef WOLFBOOT_SIGN_ECC256
#   define HAVE_ECC256
#   define FP_MAX_BITS (256 + 32)
#elif defined(WOLFBOOT_SIGN_ECC384)
#   define HAVE_ECC384
#   define FP_MAX_BITS (384 * 2)
#   if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
#       define WOLFSSL_SP_384
#       define WOLFSSL_SP_NO_256
#   endif
#   if !defined(WOLFBOOT_TPM_KEYSTORE)
#       define NO_ECC256
#   endif
#elif defined(WOLFBOOT_SIGN_ECC521)
#   define HAVE_ECC521
#   define FP_MAX_BITS (528 * 2)
#   if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
#       define WOLFSSL_SP_521
#       define WOLFSSL_SP_NO_256
#   endif
#   if !defined(WOLFBOOT_TPM_KEYSTORE)
#       define NO_ECC256
#   endif
#endif

#   define NO_RSA
#   define NO_ASN
#endif

#ifdef WOLFBOOT_SIGN_RSA2048
#   define RSA_LOW_MEM
#   ifndef WOLFBOOT_TPM
#       define WOLFSSL_RSA_VERIFY_INLINE
#       define WOLFSSL_RSA_VERIFY_ONLY
#   endif
#   ifndef WOLFBOOT_TPM_KEYSTORE
#       define WC_NO_RSA_OAEP
#   endif
#   define FP_MAX_BITS (2048 * 2)
    /* sp math */
#   if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
#       define WOLFSSL_HAVE_SP_RSA
#       define WOLFSSL_SP
#       define WOLFSSL_SP_SMALL
#       define WOLFSSL_SP_MATH
#       define WOLFSSL_SP_NO_3072
#       define WOLFSSL_SP_NO_4096
#   endif
#   define WC_ASN_HASH_SHA256
#endif

#ifdef WOLFBOOT_SIGN_RSA3072
#   define RSA_LOW_MEM
#   define WOLFSSL_RSA_VERIFY_INLINE
#   define WOLFSSL_RSA_VERIFY_ONLY
#   define WC_NO_RSA_OAEP
#   define FP_MAX_BITS (3072 * 2)
    /* sp math */
#   if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
#       define WOLFSSL_HAVE_SP_RSA
#       define WOLFSSL_SP
#       define WOLFSSL_SP_SMALL
#       define WOLFSSL_SP_MATH
#       define WOLFSSL_SP_NO_2048
#       define WOLFSSL_SP_NO_4096
#   endif
#   define WC_ASN_HASH_SHA256
#endif

#ifdef WOLFBOOT_SIGN_RSA4096
#   define RSA_LOW_MEM
#   define WOLFSSL_RSA_VERIFY_INLINE
#   define WOLFSSL_RSA_VERIFY_ONLY
#   define WC_NO_RSA_OAEP
#   define FP_MAX_BITS (4096 * 2)
    /* sp math */
#   if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH_ALL)
#       define WOLFSSL_HAVE_SP_RSA
#       define WOLFSSL_SP
#       define WOLFSSL_SP_SMALL
#       define WOLFSSL_SP_MATH
#       define WOLFSSL_SP_4096
#       define WOLFSSL_SP_NO_2048
#       define WOLFSSL_SP_NO_3072
#   endif
#   define WC_ASN_HASH_SHA256
#endif

#ifdef WOLFBOOT_HASH_SHA3_384
#   define WOLFSSL_SHA3
#   if defined(NO_RSA) && !defined(WOLFBOOT_TPM_KEYSTORE)
#       define NO_SHA256
#   endif
#endif

#ifdef WOLFBOOT_HASH_SHA384
#   define WOLFSSL_SHA384
#   if defined(NO_RSA) && !defined(WOLFBOOT_TPM_KEYSTORE)
#       define NO_SHA256
#   endif
#endif

/* If SP math is enabled determine word size */
#if defined(WOLFSSL_HAVE_SP_ECC) || defined(WOLFSSL_HAVE_SP_RSA)
#   ifdef __aarch64__
#       define HAVE___UINT128_T
#       define WOLFSSL_SP_ARM64_ASM
#       define SP_WORD_SIZE 64
#   elif defined(ARCH_x86_64) && !defined(FORCE_32BIT)
#       define SP_WORD_SIZE 64
#       ifndef NO_ASM
#           define WOLFSSL_SP_X86_64_ASM
#       endif
#   else
#       define SP_WORD_SIZE 32
#   endif

        /* SP Math needs to understand long long */
#   ifndef ULLONG_MAX
#       define ULLONG_MAX 18446744073709551615ULL
#   endif
#endif

#ifdef EXT_ENCRYPTED
#   define HAVE_PWDBASED
#else
#   define NO_PWDBASED
#endif

#ifdef WOLFBOOT_TPM
    /* Do not use heap */
    #define WOLFTPM2_NO_HEAP

    #ifdef WOLFBOOT_TPM_KEYSTORE
        /* Enable AES CFB (parameter encryption) and HMAC (for KDF) */
        #define WOLFSSL_AES_CFB

        /* Get access to mp_* math API's for ECC encrypt */
        #define WOLFSSL_PUBLIC_MP

        /* Configure RNG seed */
        #define CUSTOM_RAND_GENERATE_SEED(buf, sz) 0 /* stub, not used */
        #define WC_RNG_SEED_CB
        #define HAVE_HASHDRBG
    #endif

    #ifdef WOLFTPM_MMIO
        /* IO callback it above TIS and includes Address and if read/write */
        #define WOLFTPM_ADV_IO
    #endif

    /* add delay */
    #if !defined(XTPM_WAIT) && defined(WOLFTPM_MMIO)
        void delay(int msec);
        #define XTPM_WAIT() delay(1000);
    #endif
    #ifndef XTPM_WAIT
        #define XTPM_WAIT() /* no delay */
    #endif

    /* TPM remap printf */
    #if defined(DEBUG_WOLFTPM) && !defined(ARCH_SIM)
        #include "printf.h"
        #define printf wolfBoot_printf
    #endif
#endif

/* Disables - For minimum wolfCrypt build */
#if !defined(ENCRYPT_WITH_AES128) && !defined(ENCRYPT_WITH_AES256) && \
    !defined(WOLFBOOT_TPM_KEYSTORE)
    #define NO_AES
#endif
#if !defined(WOLFBOOT_TPM_KEYSTORE)
    #define NO_HMAC
    #define WC_NO_RNG
    #define WC_NO_HASHDRBG
    #define NO_DEV_RANDOM
    #define NO_ECC_KEY_EXPORT
#endif

#define NO_CMAC
#define NO_CODING
#define WOLFSSL_NO_PEM
#define NO_ASN_TIME
#define NO_RC4
#define NO_SHA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_RABBIT
#define NO_MD5
#define NO_SIG_WRAPPER
#define NO_CERT
#define NO_SESSION_CACHE
#define NO_HC128
#define NO_DES3
#define NO_WRITEV
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define NO_OLD_RNGNAME
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_SOCK
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_ERROR_STRINGS
#define NO_AES_CBC

#define BENCH_EMBEDDED
#define NO_CRYPT_TEST
#define NO_CRYPT_BENCHMARK
#define NO_SHA256

#ifdef __QNX__
#   define WOLFSSL_HAVE_MIN
#   define WOLFSSL_HAVE_MAX
#endif


/* Memory model */

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    /* Disable VLAs */
    #define WOLFSSL_SP_NO_DYN_STACK
#endif

#ifndef WOLFBOOT_SMALL_STACK
#   ifdef WOLFSSL_SP_MATH
#       define WOLFSSL_SP_NO_MALLOC
#       define WOLFSSL_SP_NO_DYN_STACK
#   endif
#   ifndef ARCH_SIM
#       define WOLFSSL_NO_MALLOC
#   endif
#else
#   if defined(WOLFBOOT_HUGE_STACK)
#       error "Cannot use SMALL_STACK=1 with HUGE_STACK=1"
#endif
#   define WOLFSSL_SMALL_STACK
#endif



/* from make V=1 */
#define ARCH_FLASH_OFFSET 0x0
#define ARCH_x86_64
#define BOOTLOADER_PARTITION_SIZE 0xa0000
#define BUILD_LOADER_STAGE1
#define DEBUG
#define DEBUG_UART
#define FILL_BYTE 0xFF
#define FORCE_32BIT
#define FSP_M_LOAD_BASE
#define FSP_S_LOAD_BASE 0x0FED5F00
#define IMAGE_HEADER_SIZE 512
#define MAX_COMMAND_SIZE 1024
#define MAX_DIGEST_BUFFER 973
#define MAX_RESPONSE_SIZE 1024
#define MAX_SESSION_NUM 2
#define PLATFORM_x86_fsp_qemu
#define SIZEOF_LONG 4
#define STAGE1_AUTH
#define TARGET_x86_fsp_qemu
#define __WOLFBOOT
#define WOLFBOOT_ARCH_x86_64
#define WOLFBOOT_DEBUG_TPM 1
#define WOLFBOOT_FSP 1
#define WOLFBOOT_HASH_SHA384
#define WOLFBOOT_LINUX_PAYLOAD
#define WOLFBOOT_LOAD_BASE 0x2000000
#define WOLFBOOT_MEASURED_BOOT
#define WOLFBOOT_MEASURED_PCR_A 16
#define WOLFBOOT_ORIGIN 0xffef0000
#define WOLFBOOT_SIGN_ECC384
#define WOLFBOOT_SMALL_STACK
#define WOLFBOOT_STAGE1_BASE_ADDR
#define WOLFBOOT_STAGE1_FLASH_ADDR
#define WOLFBOOT_STAGE1_LOAD_ADDR
#define WOLFBOOT_STAGE1_SIZE 0x1000
#define WOLFBOOT_TPM
#define WOLFBOOT_TPM_KEYSTORE
#define WOLFBOOT_TPM_KEYSTORE_AUTH ''
#define WOLFBOOT_TPM_KEYSTORE_NV_INDEX 0x01800200
#define WOLFBOOT_TPM_NO_CHG_PLAT_AUTH
#define WOLFSSL_SP_DIV_WORD_HALF
#define WOLFSSL_USER_SETTINGS
#define WOLFTPM2_MAX_BUFFER 1500
#define WOLFTPM_AUTODETECT
#define WOLFTPM_EXAMPLE_HAL
#define WOLFTPM_INCLUDE_IO_FILE
#define WOLFTPM_MMIO
#define WOLFTPM_SMALL_STACK
#define WOLFTPM_USER_SETTINGS
#define XMALLOC_USER

#endif /* !H_USER_SETTINGS_ */
