#ifdef USER_SETTINGS_TRIMMING_DO178
#include <user_settings_do178.h>
#endif
/* libwolfboot.c
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
/**
 * @file libwolfboot.c
 *
 * @brief wolfBoot library implementation.
 *
 * This file contains the implementation of the wolfBoot library.
 */
#include <stdint.h>


#include "hal.h"
#include "wolfboot/wolfboot.h"
#include "image.h"
#include "printf.h"

#ifdef UNIT_TEST
#else
/**
 * @def unit_dbg
 * @brief Empty macro for unit_dbg in non-test builds.
 *
 * Empty macro for unit_dbg in non-test builds.
 */
#   define unit_dbg(...) do{}while(0)
#endif

#ifndef TRAILER_SKIP
/**
 * @def TRAILER_SKIP
 * @brief Trailer skip value for partition encryption.
 *
 * Trailer skip value for partition encryption, defaults to 0 if not defined.
 */
#   define TRAILER_SKIP 0
#endif

#include <stddef.h> /* for size_t */

#if defined(EXT_FLASH) && defined(EXT_ENCRYPTED)
#else
    #define ENCRYPT_TMP_SECRET_OFFSET (WOLFBOOT_PARTITION_SIZE - (TRAILER_SKIP))
    #define SECTOR_FLAGS_SIZE WOLFBOOT_SECTOR_SIZE - (4 + 1)
    /* MAGIC (4B) + PART_FLAG (1B) */
#endif /* EXT_FLASH && EXT_ENCRYPTED */

#if !defined(__WOLFBOOT) && !defined(UNIT_TEST)
    #define XMEMSET memset
    #define XMEMCPY memcpy
    #define XMEMCMP memcmp
#endif

#ifndef NULL
#   define NULL (void *)0
#endif

#ifndef NVM_CACHE_SIZE
#define NVM_CACHE_SIZE WOLFBOOT_SECTOR_SIZE
#endif

#if defined(__WOLFBOOT) || defined (UNIT_TEST)
/* Inline use of ByteReverseWord32 */
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
static uint32_t wb_reverse_word32(uint32_t x)
{
    return ByteReverseWord32(x);
}
#endif


static const uint32_t wolfboot_magic_trail = WOLFBOOT_MAGIC_TRAIL;
/* Top addresses for FLAGS field
 *  - PART_BOOT_ENDFLAGS = top of flags for BOOT partition
 *  - PART_UPDATE_ENDFLAGS = top of flags for UPDATE_PARTITION
 */

#ifndef PART_BOOT_ENDFLAGS
#define PART_BOOT_ENDFLAGS   (WOLFBOOT_PARTITION_BOOT_ADDRESS + ENCRYPT_TMP_SECRET_OFFSET)
#endif
#define FLAGS_BOOT_EXT() PARTN_IS_EXT(PART_BOOT)

#ifdef FLAGS_HOME
#else
/* FLAGS are at the end of each partition */
#define PART_UPDATE_ENDFLAGS (WOLFBOOT_PARTITION_UPDATE_ADDRESS + ENCRYPT_TMP_SECRET_OFFSET)
#define FLAGS_UPDATE_EXT() PARTN_IS_EXT(PART_UPDATE)
#endif

#ifdef NVM_FLASH_WRITEONCE
#else
#   define trailer_write(part,addr, val) hal_flash_write(addr, (void *)&val, 1)
#   define partition_magic_write(part,addr) hal_flash_write(addr, \
                                (void*)&wolfboot_magic_trail, sizeof(uint32_t));
#endif

#ifdef EXT_FLASH
#elif !defined(WOLFBOOT_FIXED_PARTITIONS)
#else
static uint8_t* RAMFUNCTION get_trailer_at(uint8_t part, uint32_t at)
{
    uint8_t *ret = NULL;
    uint32_t sel_sec = 0;
#ifdef NVM_FLASH_WRITEONCE
    sel_sec = nvm_select_fresh_sector(part);
#endif
    if (part == PART_BOOT) {
    	ret = (void *)(PART_BOOT_ENDFLAGS -
                (WOLFBOOT_SECTOR_SIZE * sel_sec + (sizeof(uint32_t) + at)));
    }
    else if (part == PART_UPDATE) {
    	ret = (void *)(PART_UPDATE_ENDFLAGS -
                (WOLFBOOT_SECTOR_SIZE * sel_sec + (sizeof(uint32_t) + at)));
    }
    return ret;
}

static void RAMFUNCTION set_trailer_at(uint8_t part, uint32_t at, uint8_t val)
{
    if (part == PART_BOOT) {
        trailer_write(part, PART_BOOT_ENDFLAGS - (sizeof(uint32_t) + at), val);
    }
    else if (part == PART_UPDATE) {
        trailer_write(part, PART_UPDATE_ENDFLAGS - (sizeof(uint32_t) + at), val);
    }
}

static void RAMFUNCTION set_partition_magic(uint8_t part)
{
    if (part == PART_BOOT) {
        partition_magic_write(part, PART_BOOT_ENDFLAGS - sizeof(uint32_t));
    }
    else if (part == PART_UPDATE) {
        partition_magic_write(part, PART_UPDATE_ENDFLAGS - sizeof(uint32_t));
    }
}
#endif /* EXT_FLASH */



#ifdef WOLFBOOT_FIXED_PARTITIONS
/**
 * @brief Get the magic trailer of a partition.
 *
 * This function retrieves the magic trailer of a fixed partition.
 *
 * @param[in] part Partition number.
 * @return Pointer to the magic trailer of the partition.
 */
static uint32_t* RAMFUNCTION get_partition_magic(uint8_t part)
{
    return (uint32_t *)get_trailer_at(part, 0);
}

static uint8_t* RAMFUNCTION get_partition_state(uint8_t part)
{
    return (uint8_t *)get_trailer_at(part, 1);
}


static void RAMFUNCTION set_partition_state(uint8_t part, uint8_t val)
{
    set_trailer_at(part, 1, val);
}

/**
 * @brief Set the flags of an update sector.
 *
 * This function sets the flags of an update sector in a fixed partition.
 *
 * @param[in] pos Update sector position.
 * @param[in] val New flags value to set.
 * @return 0 on success, -1 on failure.
 */
static void RAMFUNCTION set_update_sector_flags(uint32_t pos, uint8_t val)
{
    set_trailer_at(PART_UPDATE, 2 + pos, val);
}

/**
 * @brief Get the flags of an update sector.
 *
 * This function retrieves the flags of an update sector in a fixed partition.
 *
 * @param[in] pos Update sector position.
 * @return Pointer to the flags of the update sector.
 */
static uint8_t* RAMFUNCTION get_update_sector_flags(uint32_t pos)
{
    return (uint8_t *)get_trailer_at(PART_UPDATE, 2 + pos);
}

/**
 * @brief Set the state of a partition.
 *
 * This function sets the state of a fixed partition.
 *
 * @param[in] part Partition number.
 * @param[in] newst New state value to set.
 * @return 0 on success, -1 on failure.
 */
int RAMFUNCTION wolfBoot_set_partition_state(uint8_t part, uint8_t newst)
{
    uint32_t *magic;
    uint8_t *state;
    magic = get_partition_magic(part);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        set_partition_magic(part);
    state = get_partition_state(part);
    if (*state != newst)
        set_partition_state(part, newst);
    return 0;
}

int RAMFUNCTION wolfBoot_set_update_sector_flag(uint16_t sector, uint8_t newflag)
{
    uint32_t *magic;
    uint8_t *flags;
    uint8_t fl_value;
    uint8_t pos = sector >> 1;

    magic = get_partition_magic(PART_UPDATE);
    if (*magic != wolfboot_magic_trail)
        set_partition_magic(PART_UPDATE);

    flags = get_update_sector_flags(pos);
    if (sector == (pos << 1))
        fl_value = (*flags & 0xF0) | (newflag & 0x0F);
    else
        fl_value = ((newflag & 0x0F) << 4) | (*flags & 0x0F);
    if (fl_value != *flags)
        set_update_sector_flags(pos, fl_value);
    return 0;
}

/**
 * @brief Get the state of a partition.
 *
 * This function retrieves the state of a fixed partition.
 *
 * @param[in] part Partition number.
 * @param[out] st Pointer to store the partition state.
 * @return 0 on success, -1 on failure.
 */
int RAMFUNCTION wolfBoot_get_partition_state(uint8_t part, uint8_t *st)
{
    uint32_t *magic;
    uint8_t *state;
    magic = get_partition_magic(part);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        return -1;
    state = get_partition_state(part);
    *st = *state;
    return 0;
}

int wolfBoot_get_update_sector_flag(uint16_t sector, uint8_t *flag)
{
    uint32_t *magic;
    uint8_t *flags;
    uint8_t pos = sector >> 1;
    magic = get_partition_magic(PART_UPDATE);
    if (*magic != WOLFBOOT_MAGIC_TRAIL)
        return -1;
    flags = get_update_sector_flags(pos);
    if (sector == (pos << 1))
        *flag = *flags & 0x0F;
    else
        *flag = (*flags & 0xF0) >> 4;
    return 0;
}

/**
 * @brief Erase a partition.
 *
 * This function erases a partition.
 *
 * @param[in] part Partition number.
 */
void RAMFUNCTION wolfBoot_erase_partition(uint8_t part)
{
    uint32_t address = 0;
    int size = 0;

    if (part == PART_BOOT) {
        address = (uint32_t)WOLFBOOT_PARTITION_BOOT_ADDRESS;
        size = WOLFBOOT_PARTITION_SIZE;
    }
    if (part == PART_UPDATE) {
        address = (uint32_t)WOLFBOOT_PARTITION_UPDATE_ADDRESS;
        size = WOLFBOOT_PARTITION_SIZE;
    }
    if (part == PART_SWAP) {
        address = (uint32_t)WOLFBOOT_PARTITION_SWAP_ADDRESS;
        size = WOLFBOOT_SECTOR_SIZE;
    }

    if (size > 0) {
        if (PARTN_IS_EXT(part)) {
            ext_flash_unlock();
            ext_flash_erase(address, size);
            ext_flash_lock();
        } else {
            hal_flash_erase(address, size);
        }
    }
}

/**
 * @brief Update trigger function.
 *
 * This function updates the boot partition state to "IMG_STATE_UPDATING".
 * If the FLAGS_HOME macro is defined, it erases the last sector of the boot
 * partition before updating the partition state. It also checks FLAGS_UPDATE_EXT
 * and calls the appropriate flash unlock and lock functions before
 * updating the partition state.
 */
void RAMFUNCTION wolfBoot_update_trigger(void)
{
    uint8_t st = IMG_STATE_UPDATING;
#if defined(NVM_FLASH_WRITEONCE) || defined(WOLFBOOT_FLAGS_INVERT)
    uintptr_t lastSector = PART_UPDATE_ENDFLAGS -
        (PART_UPDATE_ENDFLAGS % WOLFBOOT_SECTOR_SIZE);

#ifndef FLAGS_HOME
    /* if PART_UPDATE_ENDFLAGS stradles a sector, (all non FLAGS_HOME builds)
     * align it to the correct sector */
    if (PART_UPDATE_ENDFLAGS % WOLFBOOT_SECTOR_SIZE == 0)
        lastSector -= WOLFBOOT_SECTOR_SIZE;
#endif
#endif
#ifdef NVM_FLASH_WRITEONCE
    uint8_t selSec = 0;
#endif

    /* erase the sector flags */
    if (FLAGS_UPDATE_EXT()) {
        ext_flash_unlock();
    } else {
        hal_flash_unlock();
    }

    /* NVM_FLASH_WRITEONCE needs erased flags since it selects the fresh
     * partition based on how many flags are non-erased
     * FLAGS_INVERT needs erased flags because the bin-assemble's fill byte may
     * not match what's in wolfBoot */
#if defined(NVM_FLASH_WRITEONCE) || defined(WOLFBOOT_FLAGS_INVERT)
    if (FLAGS_UPDATE_EXT()) {
        ext_flash_erase(lastSector, SECTOR_FLAGS_SIZE);
    } else {
#ifdef NVM_FLASH_WRITEONCE
        selSec = nvm_select_fresh_sector(PART_UPDATE);
        XMEMCPY(NVM_CACHE,
            (uint8_t*)(lastSector - WOLFBOOT_SECTOR_SIZE * selSec),
            WOLFBOOT_SECTOR_SIZE);
        XMEMSET(NVM_CACHE, FLASH_BYTE_ERASED, SECTOR_FLAGS_SIZE);
        /* write to the non selected sector */
        hal_flash_write(lastSector - WOLFBOOT_SECTOR_SIZE * !selSec, NVM_CACHE,
            WOLFBOOT_SECTOR_SIZE);
        /* erase the previously selected sector */
        hal_flash_erase(lastSector - WOLFBOOT_SECTOR_SIZE * selSec,
            WOLFBOOT_SECTOR_SIZE);
#elif defined(WOLFBOOT_FLAGS_INVERT)
        hal_flash_erase(lastSector, SECTOR_FLAGS_SIZE);
#endif
    }
#endif

    wolfBoot_set_partition_state(PART_UPDATE, st);

    if (FLAGS_UPDATE_EXT()) {
        ext_flash_lock();
    } else {
        hal_flash_lock();
    }
}

/**
 * @brief Success function.
 *
 * This function updates the boot partition state to "IMG_STATE_SUCCESS".
 * If the FLAGS_BOOT_EXT macro is defined, it calls the appropriate flash unlock
 * and lock functions before updating the partition state. If the EXT_ENCRYPTED
 * macro is defined, it calls wolfBoot_erase_encrypt_key function.
 */
void RAMFUNCTION wolfBoot_success(void)
{
    uint8_t st = IMG_STATE_SUCCESS;
    if (FLAGS_BOOT_EXT()) {
        ext_flash_unlock();
        wolfBoot_set_partition_state(PART_BOOT, st);
        ext_flash_lock();
    } else {
        hal_flash_unlock();
        wolfBoot_set_partition_state(PART_BOOT, st);
        hal_flash_lock();
    }
#ifdef EXT_ENCRYPTED
    wolfBoot_erase_encrypt_key();
#endif
}
#endif /* WOLFBOOT_FIXED_PARTITIONS */

/**
 * @brief Find header function.
 *
 * This function searches for a specific header type in the given buffer.
 * It returns the length of the header and sets the 'ptr' parameter to the
 * position of the header if found.
 * @param haystack Pointer to the buffer to search for the header.
 * @param type The type of header to search for.
 * @param ptr Pointer to store the position of the header.
 *
 * @return uint16_t The length of the header found, or 0 if not found.
 *
 */
uint16_t wolfBoot_find_header(uint8_t *haystack, uint16_t type, uint8_t **ptr)
{
    uint8_t *p = haystack;
    uint16_t len;
    const volatile uint8_t *max_p = (haystack - IMAGE_HEADER_OFFSET) +
                                                    IMAGE_HEADER_SIZE;
    *ptr = NULL;
    if (p > max_p) {
        unit_dbg("Illegal address (too high)\n");
        return 0;
    }
    while ((p + 4) < max_p) {
        if ((p[0] == 0) && (p[1] == 0)) {
            unit_dbg("Explicit end of options reached\n");
            break;
        }
        if (*p == HDR_PADDING) {
            /* Padding byte (skip one position) */
            p++;
            continue;
        }
        /* Sanity check to prevent dereferencing unaligned half-words */
        if ((((size_t)p) & 0x01) != 0) {
            p++;
            continue;
        }
        len = p[2] | (p[3] << 8);
        if ((4 + len) > (uint16_t)(IMAGE_HEADER_SIZE - IMAGE_HEADER_OFFSET)) {
            unit_dbg("This field is too large (bigger than the space available "
                     "in the current header)\n");
            unit_dbg("%d %d %d\n", len, IMAGE_HEADER_SIZE, IMAGE_HEADER_OFFSET);
            break;
        }
        if (p + 4 + len > max_p) {
            unit_dbg("This field is too large and would overflow the image "
                     "header\n");
            break;
        }
        if ((p[0] | (p[1] << 8)) == type) {
            *ptr = (p + 4);
            return len;
        }
        p += 4 + len;
    }
    return 0;
}

/**
 * @brief Convert little-endian to native-endian (uint32_t).
 *
 * This function converts a little-endian 32-bit value to the native-endian format.
 * It is used to handle endianness differences when reading data from memory.
 *
 * @param val The value to convert.
 *
 * @return The converted value.
 */
static inline uint32_t im2n(uint32_t val)
{
#ifdef BIG_ENDIAN_ORDER
    val = (((val & 0x000000FF) << 24) |
           ((val & 0x0000FF00) <<  8) |
           ((val & 0x00FF0000) >>  8) |
           ((val & 0xFF000000) >> 24));
#endif
  return val;
}

/**
 * @brief Convert little-endian to native-endian (uint16_t).
 *
 * This function converts a little-endian 16-bit value to the native-endian format.
 * It is used to handle endianness differences when reading data from memory.
 *
 * @param val The value to convert.
 * @return uint16_t The converted value.

 */
static inline uint16_t im2ns(uint16_t val)
{
#ifdef BIG_ENDIAN_ORDER
    val = (((val & 0x000000FF) << 8) |
           ((val & 0x0000FF00) >>  8));
#endif
  return val;
}
/**
 * @brief Get blob version.
 *
 * This function retrieves the version number from the blob.
 * It checks the magic number in the blob to ensure it is valid before reading
 * the version field.
 *
 * @param blob Pointer to the buffer containing the blob.
 *
 * @return The version number of the blob, or 0 if the blob is invalid.
 *
 */
uint32_t wolfBoot_get_blob_version(uint8_t *blob)
{
    uint32_t *volatile version_field = NULL;
    uint32_t *magic = NULL;
    uint8_t *img_bin = blob;
#if defined(EXT_ENCRYPTED) && defined(MMU)
    if (!encrypt_initialized)
        if (crypto_init() < 0)
            return 0;
    decrypt_header(blob);
    img_bin = dec_hdr;
#endif
    magic = (uint32_t *)img_bin;
    if (*magic != WOLFBOOT_MAGIC)
        return 0;
    if (wolfBoot_find_header(img_bin + IMAGE_HEADER_OFFSET, HDR_VERSION,
            (void *)&version_field) == 0)
        return 0;
    if (version_field)
        return im2n(*version_field);
    return 0;
}

/**
 * @brief Get blob type.
 *
 * This function retrieves the type of the blob.
 * It checks the magic number in the blob to ensure it is valid before reading
 * the type field.
 *
 * @param blob Pointer to the buffer containing the blob.
 *
 * @return The type of the blob, or 0 if the blob is invalid.
 */
uint32_t wolfBoot_get_blob_type(uint8_t *blob)
{
    uint32_t *volatile type_field = NULL;
    uint32_t *magic = NULL;
    uint8_t *img_bin = blob;
#if defined(EXT_ENCRYPTED) && defined(MMU)
    if (!encrypt_initialized)
        if (crypto_init() < 0)
            return 0;
    decrypt_header(blob);
    img_bin = dec_hdr;
#endif
    magic = (uint32_t *)img_bin;
    if (*magic != WOLFBOOT_MAGIC)
        return 0;
    if (wolfBoot_find_header(img_bin + IMAGE_HEADER_OFFSET, HDR_IMG_TYPE,
            (void *)&type_field) == 0)
        return 0;
    if (type_field)
        return im2ns(*type_field);

    return 0;
}

/**
 * @brief Get blob difference base version.
 *
 * This function retrieves the difference base version from the blob.
 * It checks the magic number in the blob to ensure it is valid before reading
 * the difference base field.
 *
 * @param blob Pointer to the buffer containing the blob.
 *
 * @return The difference base version of the blob, or 0 if not found
 * or the blob is invalid.
 *
 */

uint32_t wolfBoot_get_blob_diffbase_version(uint8_t *blob)
{
    uint32_t *volatile delta_base = NULL;
    uint32_t *magic = NULL;
    uint8_t *img_bin = blob;
#if defined(EXT_ENCRYPTED) && defined(MMU)
    if (!encrypt_initialized)
        if (crypto_init() < 0)
            return 0;
    decrypt_header(blob);
    img_bin = dec_hdr;
#endif
    magic = (uint32_t *)img_bin;
    if (*magic != WOLFBOOT_MAGIC)
        return 0;
    if (wolfBoot_find_header(img_bin + IMAGE_HEADER_OFFSET, HDR_IMG_DELTA_BASE,
            (void *)&delta_base) == 0)
        return 0;
    if (delta_base)
        return *delta_base;
    return 0;
}


#ifdef WOLFBOOT_FIXED_PARTITIONS
/**
 * @brief Get image pointer from a partition.
 *
 * This function retrieves the pointer to the image in the specified partition.
 * It handles both regular and extended partitions by reading from memory or
 * external flash if needed.
 *
 * @param part The partition to get the image pointer for.
 *
 * @return uint8_t* Pointer to the image in the specified partition, or
 * NULL if the partition is invalid or empty.
 *
 */
static uint8_t* wolfBoot_get_image_from_part(uint8_t part)
{
    uint8_t *image = (uint8_t *)0x00000000;

    if (part == PART_UPDATE) {
        image = (uint8_t *)WOLFBOOT_PARTITION_UPDATE_ADDRESS;

    } else if (part == PART_BOOT) {
        image = (uint8_t *)WOLFBOOT_PARTITION_BOOT_ADDRESS;
    }
#ifdef EXT_FLASH
    if (PARTN_IS_EXT(part)) {
        ext_flash_check_read((uintptr_t)image, hdr_cpy, IMAGE_HEADER_SIZE);
        hdr_cpy_done = 1;
        image = hdr_cpy;
    }
#endif

    return image;
}

/**
 * @brief Get image version for a partition.
 *
 * This function retrieves the version number of the image in the specified
 * partition. It uses the 'wolfBoot_get_blob_version' function to extract the
 * version from the image blob.
 *
 * @param part The partition to get the image version for.
 *
 * @return The version number of the image in the partition,
 * or 0 if the partition is invalid or empty.
 *
 */

uint32_t wolfBoot_get_image_version(uint8_t part)
{
    /* Don't check image against NULL to allow using address 0x00000000 */
    return wolfBoot_get_blob_version(wolfBoot_get_image_from_part(part));
}

/**
 * @brief Get difference base version for a partition.
 *
 * This function retrieves the difference base version from the image in the
 * specified partition. It uses the 'wolfBoot_get_blob_diffbase_version'
 * function to extract the difference base version from the image blob.
 *
 * @param part The partition to get the difference base version for.
 *
 * @return The difference base version of the image in the partition, or
 * 0 if not found or the partition is invalid or empty.
 *
 */

uint32_t wolfBoot_get_diffbase_version(uint8_t part)
{
    /* Don't check image against NULL to allow using address 0x00000000 */
    return wolfBoot_get_blob_diffbase_version(
                wolfBoot_get_image_from_part(part));
}
/**
 * @brief Get image type for a partition.
 *
 * This function retrieves the image type from the image in the specified
 * partition. It uses the 'wolfBoot_get_blob_type' function to extract the image
 * type from the image blob.
 *
 * @param part The partition to get the image type for.
 *
 * @return uint16_t The image type of the image in the partition, or
 * 0 if the partition is invalid or empty.
 *
 */
uint16_t wolfBoot_get_image_type(uint8_t part)
{
    uint8_t *image = wolfBoot_get_image_from_part(part);

    if (image) {
      return wolfBoot_get_blob_type(image);
    }

    return 0;
}
#endif /* WOLFBOOT_FIXED_PARTITIONS */

