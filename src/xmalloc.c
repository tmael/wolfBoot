#ifdef USER_SETTINGS_TRIMMING_DO178
#include <user_settings_do178.h>
#endif

/* xmalloc.c
 *
 * Fixed-pool implementation of malloc/free for wolfBoot
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

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <wolfssl/wolfcrypt/settings.h>
#ifndef USE_FAST_MATH
    #include <wolfssl/wolfcrypt/sp.h>
    #include <wolfssl/wolfcrypt/sp_int.h>
#else
    #include <wolfssl/wolfcrypt/tfm.h>
#endif
#include "target.h"


struct xmalloc_slot {
    uint8_t *addr;
    uint32_t size;
    uint32_t in_use;
};

#define MP_DIGIT_SIZE (sizeof(mp_digit))

#ifdef WOLFBOOT_HASH_SHA256
#   include <wolfssl/wolfcrypt/sha256.h>
#   define HASH_BLOCK_SIZE WC_SHA256_BLOCK_SIZE
#elif defined WOLFBOOT_HASH_SHA384
#   include <wolfssl/wolfcrypt/sha512.h>
#   define HASH_BLOCK_SIZE (WC_SHA384_BLOCK_SIZE / sizeof(uint32_t))
#else
#   error "No hash mechanism selected."
#endif

#if defined(WOLFBOOT_SIGN_ECC256) || defined(WOLFBOOT_SIGN_ECC384)

#ifndef USE_FAST_MATH
    /* SP MATH */
    #ifdef WOLFBOOT_SIGN_ECC384
        #define MP_CURVE_SPECS_SIZE (108)
        #ifdef WOLFSSL_SP_ARM_CORTEX_M_ASM
        #else
            #define MP_POINT_SIZE (364)
            #define MP_DIGITS_BUFFER_SIZE_0 (MP_DIGIT_SIZE * 18 * 15)
            #define MP_DIGITS_BUFFER_SIZE_1 (MP_DIGIT_SIZE * (4 * 15 + 3))
            #define MP_DIGITS_BUFFER_SIZE_2 (MP_DIGIT_SIZE * (2 * 15 * 6))
            #define MP_MONTGOMERY_SIZE (sizeof(int64_t) * 2 * 12)
        #endif
    #endif /* WOLFBOOT_SIGN_ECC384 */
    #ifndef WC_NO_CACHE_RESISTANT
    static uint8_t mp_points_3[MP_POINT_SIZE];
    #endif
    static uint8_t mp_points_0[MP_POINT_SIZE * 2];
    static uint8_t mp_points_1[MP_POINT_SIZE * 2];
    static uint8_t mp_points_2[MP_POINT_SIZE * (16 + 1)];
    static uint8_t mp_digits_buffer_0[MP_DIGITS_BUFFER_SIZE_0];
    static uint8_t mp_digits_buffer_1[MP_DIGITS_BUFFER_SIZE_1];
    #if !defined(WOLFSSL_SP_ARM_CORTEX_M_ASM) && (defined(WOLFBOOT_SIGN_ECC256) || defined(WOLFBOOT_SIGN_ECC384))
    static uint8_t mp_digits_buffer_2[MP_DIGITS_BUFFER_SIZE_2];
    static uint8_t mp_montgomery[MP_MONTGOMERY_SIZE];
    #elif defined(WOLFBOOT_SIGN_ECC384)
    static uint8_t mp_montgomery[MP_MONTGOMERY_SIZE];
    #endif
#else
#endif

static uint8_t mp_curve_specs[MP_CURVE_SPECS_SIZE];




static uint32_t sha_block[HASH_BLOCK_SIZE];
static struct xmalloc_slot xmalloc_pool[] = {
#if defined(WOLFBOOT_HASH_SHA256) || defined(WOLFBOOT_HASH_SHA384)
    { (uint8_t *)sha_block, HASH_BLOCK_SIZE * sizeof(uint32_t), 0 },
#endif
    { (uint8_t *)mp_curve_specs, MP_CURVE_SPECS_SIZE, 0 },
#ifndef USE_FAST_MATH
    { (uint8_t *)mp_points_0, MP_POINT_SIZE * 2, 0 },
    #ifdef WOLFSSL_SP_ARM_CORTEX_M_ASM
    { (uint8_t *)mp_points_1, MP_POINT_SIZE * 2, 0 },
        #ifdef WOLFBOOT_SIGN_ECC384
    { (uint8_t *)mp_montgomery, MP_MONTGOMERY_SIZE, 0 },
        #endif
    #else
    { (uint8_t *)mp_points_1, MP_POINT_SIZE * 3, 0 },
    { (uint8_t *)mp_digits_buffer_2, MP_DIGITS_BUFFER_SIZE_2, 0 },
    { (uint8_t *)mp_montgomery, MP_MONTGOMERY_SIZE, 0 },
    #endif
    { (uint8_t *)mp_points_2, MP_POINT_SIZE * (16 + 1), 0 },
    { (uint8_t *)mp_digits_buffer_0, MP_DIGITS_BUFFER_SIZE_0, 0},
    { (uint8_t *)mp_digits_buffer_1, MP_DIGITS_BUFFER_SIZE_1, 0},
    #ifndef WC_NO_CACHE_RESISTANT
    { (uint8_t *)mp_points_3, MP_POINT_SIZE, 0 },
    #endif
#else
#endif
    { NULL, 0, 0}
};

#else 
#   error "No cipher selected."
#endif

void* XMALLOC(size_t n, void* heap, int type)
{
    int i = 0;

    while (xmalloc_pool[i].addr) {
        if ((n == xmalloc_pool[i].size) &&
                (xmalloc_pool[i].in_use == 0)) {
            xmalloc_pool[i].in_use++;
            return xmalloc_pool[i].addr;
        }
        i++;
    }
    (void)heap;
    (void)type;
    return NULL;
}

void XFREE(void *ptr, void *heap, int type)
{
    int i = 0;
    while (xmalloc_pool[i].addr) {
        if ((ptr == (void *)(xmalloc_pool[i].addr)) && xmalloc_pool[i].in_use) {
            xmalloc_pool[i].in_use = 0;
            return;
        }
        i++;
    }
    (void)heap;
    (void)type;
}
