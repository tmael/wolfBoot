/* ata.c
 *
 * Copyright (C) 2023 wolfSSL Inc.
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
 *
 */
/**
 * @file ata.c
 * @brief This file contains the implementation of the ATA
 * (Advanced Technology Attachment) driver used for interacting with AHCI
 * (Advanced Host Controller Interface) based SATA drives.
 * It supports functions for drive initialization, read and write operations,
 * and device identification.
 */
#ifndef ATA_C
#define ATA_C
#include <stdint.h>
#include <x86/common.h>
#include <x86/ahci.h>
#include <x86/ata.h>
#include <printf.h>
#include <string.h>

#define MAX_ATA_DRIVES 4
#define MAX_SECTOR_SIZE 512

#define CACHE_INVALID 0xBADF00DBADC0FFEEULL

#ifdef DEBUG_ATA
/**
 * @brief This macro is used to conditionally print debug messages for the ATA
 * driver. If DEBUG_ATA is defined, it calls the wolfBoot_printf function with
 * the specified format and arguments. Otherwise, it is defined as an empty
 * do-while loop.
 *
 * @param[in] ... Format and arguments for the debug printf.
 */
#define ATA_DEBUG_PRINTF(...) wolfBoot_printf(__VA_ARGS__)
#else
#define ATA_DEBUG_PRINTF(...) do {} while(0)
#endif /* DEBUG_ATA */


static int ata_drive_count = -1;

/**
 * @brief This structure holds the necessary information for an ATA drive,
 * including AHCI base address, AHCI port number, and sector cache.
 */
struct ata_drive {
    uint32_t ahci_base;
    unsigned ahci_port;
    uint32_t clb_port;
    uint32_t ctable_port;
    uint32_t fis_port;
    uint32_t sector_size_shift;
    uint8_t  sector_cache[MAX_SECTOR_SIZE];
    uint64_t cached;
};

/**
 * @brief This array holds instances of the `struct ata_drive` representing
 * multiple ATA drives (up to `MAX_ATA_DRIVES`).
 */
struct ata_drive ATA_Drv[MAX_ATA_DRIVES];

/**
 * @brief This packed structure defines a single entry in the HBA
 * (Host Bus Adapter) HBA PRDT (Physical Region Descriptor Table) used for
 * DMA data transfer.
 */
struct __attribute__((packed)) hba_prdt_entry {
    uint32_t dba;
    uint32_t dbau;
    uint32_t _res0;
    uint32_t dbc:22, _res1:9, i:1;

};

/**
 * @brief This packed structure defines the layout of an HBA command table,
 * which contains command headers and PRDT entries for DMA data transfer.
 */
struct __attribute__((packed)) hba_cmd_table {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t _res[48];
    struct hba_prdt_entry prdt_entry[8];
};

/**
 * @brief This packed structure defines the format of an H2D Register FIS
 * used for ATA commands.
 */
struct __attribute__((packed)) fis_reg_h2d {
    uint8_t fis_type;

    uint8_t pmport:4, _res0:3, c:1;

    uint8_t command;
    uint8_t feature_l;

    uint8_t lba0;
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;

    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t featureh;

    uint16_t count;
    uint8_t icc;
    uint8_t control;

    uint32_t _res1;
};

/**
 * @brief This packed structure defines the format of a D2H Register FIS
 * used for ATA commands completion.
 */
struct __attribute__((packed)) fis_reg_d2h {
    uint8_t fis_type;

    uint8_t pmport:4, _res0:2, i:1, _res1:1;

    uint8_t status;
    uint8_t error;

    uint8_t lba0;
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;

    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t _res2;

    uint16_t count;
    uint16_t _res3;

    uint32_t _res4;
};

/**
 * @brief This packed structure defines the format of a Data FIS used for
 * data transfer.
 */
struct __attribute__((packed)) fis_data {
    uint8_t fis_type;
    uint8_t pmport:4, _res0:4;
    uint16_t res1;
    uint32_t data[0];
};

/**
 * @brief This function initializes a new ATA drive instance with the provided
 * parameters and stores it in the ATA_Drv array.
 *
 * @param[in] ahci_base The base address of the AHCI controller.
 * @param[in] ahci_port The port number of the AHCI controller.
 * @param[in] clb The command list base address for the drive.
 * @param[in] ctable The command table base address for the drive.
 * @param[in] fis The FIS base address for the drive.
 *
 * @return The index of the new ATA drive if successful, or -1 if the maximum
 * number of drives has been reached.
 */
int ata_drive_new(uint32_t ahci_base, unsigned ahci_port, uint32_t clb,
                  uint32_t ctable, uint32_t fis)
{
    struct ata_drive *ata = (void *)0;
    if (++ata_drive_count >= MAX_ATA_DRIVES)
        return -1;

    ata = &ATA_Drv[ata_drive_count];
    ata->ahci_base = ahci_base;
    ata->ahci_port = ahci_port;
    ata->clb_port = clb;
    ata->ctable_port = ctable;
    ata->fis_port = fis;
    ata->sector_size_shift = 9; /* 512 */
    ata->cached = CACHE_INVALID;
    return ata_drive_count;
}

/**
 * @brief This static function finds an available command slot for the specified
 * ATA drive and returns the slot number.
 *
 * @param[in] drv The index of the ATA drive in the ATA_Drv array.
 *
 * @return The index of the available command slot if found, or -1 if no slot is
 * available.
 */
static int find_cmd_slot(int drv)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    uint32_t slots, sact, ci;
    uint32_t i;
    sact = mmio_read32((AHCI_PxSACT(ata->ahci_base, ata->ahci_port)));
    ci = mmio_read32((AHCI_PxCI(ata->ahci_base, ata->ahci_port)));
    slots = sact | ci;
    for (i = 0; i < 32; i++) {
        if ((slots & 1) == 0)
            return i;
        slots >>= 1;
    }
    wolfBoot_printf("ATA: Cannot allocate command slot\r\n");
    return -1;
}

/**
 * @brief This static function prepares a command slot for DMA data transfer by
 * initializing the command header and command table entries.
 *
 * @param[in] drv The index of the ATA drive in the ATA_Drv array.
 * @param[in] buf The buffer containing the data to be transferred.
 * @param[in] sz The size of the data to be transferred in bytes.
 *
 * @return The index of the prepared command slot if successful, or -1 if an error
 * occurs.
 */
static int prepare_cmd_slot(int drv, const uint8_t *buf, int sz)
{
    struct hba_cmd_header *cmd;
    struct hba_cmd_table *tbl;
    struct ata_drive *ata = &ATA_Drv[drv];
    int slot = find_cmd_slot(drv);
    if (slot < 0) {
        wolfBoot_printf("ATA: Operation aborted: no free command slot\r\n");
        return -1;
    }
    cmd = (struct hba_cmd_header *)(uintptr_t)ata->clb_port;
    cmd += slot;
    memset(cmd, 0, sizeof(struct hba_cmd_header));

    cmd->cfl = FIS_LEN_H2D / 4;
    cmd->ctba = (uint32_t)(ata->ctable_port);
    tbl = (struct hba_cmd_table *)(uintptr_t)(ata->ctable_port);
    memset(tbl, 0, sizeof(struct hba_cmd_table));
    cmd->prdtl = 1;
    tbl->prdt_entry[0].dba = (uint32_t)(uintptr_t)buf;
    tbl->prdt_entry[0].dbc = sz - 1;
    return slot;
}


/**
 * @brief This static function executes the command in the specified command
 * slot for the ATA drive and waits for the command to complete.
 *
 * @param[in] drv The index of the ATA drive in the ATA_Drv array.
 * @param[in] slot The index of the command slot to execute.
 *
 * @return 0 on success, or -1 if an error occurs during command execution.
 */
static int exec_cmd_slot(int drv, int slot)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    uint32_t reg;
    /* Clear IS */
    reg = mmio_read32(AHCI_PxIS(ata->ahci_base, ata->ahci_port));
    mmio_write32(AHCI_PxIS(ata->ahci_base, ata->ahci_port), reg);

    /* Wait until port not busy */
    while (mmio_read32(AHCI_PxTFD(ata->ahci_base, ata->ahci_port)) & (ATA_DEV_BUSY | ATA_DEV_DRQ))
        ;

    mmio_write32((AHCI_PxCI(ata->ahci_base, ata->ahci_port)), 1 << slot);

    while ((mmio_read32(AHCI_PxCI(ata->ahci_base, ata->ahci_port)) & (1 << slot)) != 0) {
        if (mmio_read32(AHCI_PxIS(ata->ahci_base, ata->ahci_port)) & AHCI_PORT_IS_TFES) {
            wolfBoot_printf("ATA: port error\r\n");
            return -1;
        }
    }
    return 0;
}

#ifndef ATA_BUF_SIZE
#define ATA_BUF_SIZE 8192
#endif
static uint8_t buffer[ATA_BUF_SIZE];

static void invert_buf(uint8_t *src, uint8_t *dst, unsigned len)
{
    unsigned i;
    memset(dst, 0, len);
    for (i = 0; i < len; i+=2) {
       dst[i] = src[i + 1];
       dst[i + 1] = src[i];
    }
    dst[len - 1]  = 0;
}

#define ATA_ID_SERIAL_NO_POS 20
#define ATA_ID_SERIAL_NO_LEN 20
#define ATA_ID_MODEL_NO_POS  54
#define ATA_ID_MODEL_NO_LEN  40


/**
 * @brief This function identifies the ATA device connected to the specified
 * ATA drive and retrieves its device information, such as serial number and
 * model name.
 *
 * @param[in] drv The index of the ATA drive in the ATA_Drv array.
 *
 * @return 0 on success, or -1 if an error occurs during device identification.
 */
int ata_identify_device(int drv)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    struct hba_cmd_header *cmd;
    struct hba_cmd_table *tbl;
    struct fis_reg_h2d *cmdfis;
    uint8_t serial_no[ATA_ID_SERIAL_NO_LEN];
    uint8_t model_no[ATA_ID_MODEL_NO_LEN];
    int slot = prepare_cmd_slot(drv, buffer, 512);
    int ret = 0;
    cmd = (struct hba_cmd_header *)(uintptr_t)ata->clb_port;
    cmd += slot;

    tbl = (struct hba_cmd_table *)(uintptr_t)cmd->ctba;
    cmdfis = (struct fis_reg_h2d *)(&tbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_IDENTIFY_DEVICE;
    ret = exec_cmd_slot(drv, slot);
    if (ret == 0) {
        uint16_t *id_buf = (uint16_t *)buffer;
        ATA_DEBUG_PRINTF("Device identified\r\n");
        ATA_DEBUG_PRINTF("Cylinders: %d\r\n", id_buf[1]);
        ATA_DEBUG_PRINTF("Heads: %d\r\n", id_buf[3]);
        ATA_DEBUG_PRINTF("Sectors per track: %d\r\n", id_buf[6]);
        ATA_DEBUG_PRINTF("Vendor: %04x:%04x:%04x\r\n", id_buf[7], id_buf[8],
                id_buf[9]);
        invert_buf(&buffer[ATA_ID_SERIAL_NO_POS], serial_no,
                ATA_ID_SERIAL_NO_LEN);
        ATA_DEBUG_PRINTF("Serial n.: %s\r\n", serial_no);

        invert_buf(&buffer[ATA_ID_MODEL_NO_POS], model_no,
                ATA_ID_MODEL_NO_LEN);
        ATA_DEBUG_PRINTF("Model: %s\r\n", model_no);
    }
    return ret;
}

static int ata_drive_read_sector(int drv, uint64_t start, uint32_t count,
        uint8_t *buf)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    struct hba_cmd_header *cmd;
    struct hba_cmd_table *tbl;
    struct fis_reg_h2d *cmdfis;
    int i;
    int slot = prepare_cmd_slot(drv, buf, count << ata->sector_size_shift);
    cmd = (struct hba_cmd_header *)(uintptr_t)ata->clb_port;
    cmd += slot;

    tbl = (struct hba_cmd_table *)(uintptr_t)cmd->ctba;
    cmdfis = (struct fis_reg_h2d *)(&tbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_READ_DMA_EX;
    cmdfis->lba0 = (uint8_t)(start & 0xFF);
    cmdfis->lba1 = (uint8_t)((start >> 8) & 0xFF);
    cmdfis->lba2 = (uint8_t)((start >> 16) & 0xFF);
    cmdfis->lba3 = (uint8_t)((start >> 24) & 0xFF);
    cmdfis->lba4 = (uint8_t)((start >> 32) & 0xFF);
    cmdfis->lba5 = (uint8_t)((start >> 40) & 0xFF);
    cmdfis->device = (1 << 6); /* LBA mode */
    cmdfis->count = (uint16_t)(count & 0xFFFF);
    exec_cmd_slot(drv, slot);
    return count << ata->sector_size_shift;
}

static int ata_drive_write_sector(int drv, uint64_t start, uint32_t count,
        const uint8_t *buf)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    struct hba_cmd_header *cmd;
    struct hba_cmd_table *tbl;
    struct fis_reg_h2d *cmdfis;
    uint8_t *buf_ptr;
    int i;
    int slot = prepare_cmd_slot(drv, buf, count << ata->sector_size_shift);
    cmd = (struct hba_cmd_header *)(uintptr_t)ata->clb_port;
    cmd += slot;
    tbl = (struct hba_cmd_table *)(uintptr_t)cmd->ctba;
    cmdfis = (struct fis_reg_h2d *)(&tbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_WRITE_DMA;
    cmdfis->lba0 = (uint8_t)(start & 0xFF);
    cmdfis->lba1 = (uint8_t)((start >> 8) & 0xFF);
    cmdfis->lba2 = (uint8_t)((start >> 16) & 0xFF);
    cmdfis->lba3 = (uint8_t)((start >> 24) & 0xFF);
    cmdfis->lba4 = (uint8_t)((start >> 32) & 0xFF);
    cmdfis->lba5 = (uint8_t)((start >> 40) & 0xFF);
    cmdfis->device = (1 << 6); /* LBA mode */
    cmdfis->count = (uint16_t)(count & 0xFFFF);

    exec_cmd_slot(drv, slot);
    return count << ata->sector_size_shift;
}

static void ata_invalidate_cache(int drv)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    ata->cached = CACHE_INVALID;
}

static void ata_cache_pull(int drv, uint64_t sector)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    if (ata->cached == sector)
        return;
    if (ata_drive_read_sector(drv, sector, 1, ata->sector_cache) < 0) {
        ata_invalidate_cache(drv);
        return;
    }
    ata->cached = sector;
}

static void ata_cache_commit(int drv)
{
    struct ata_drive *ata = &ATA_Drv[drv];
    if (ata->cached == CACHE_INVALID)
        return;
    ata_drive_write_sector(drv, ata->cached, 1, ata->sector_cache);
}

/**
 * @brief This function reads data from the specified ATA drive starting from
 * the given sector and copies it into the provided buffer. It handles partial
 * reads and multiple sector transfers.
 *
 * @param[in] drv The index of the ATA drive in the ATA_Drv array.
 * @param[in] start The starting sector number to read from.
 * @param[in] size The size of the data to read in bytes.
 * @param[out] buf The buffer to store the read data.
 *
 * @return The number of bytes read into the buffer, or -1 if an error occurs.
 */
int ata_drive_read(int drv, uint64_t start, uint32_t size, uint8_t *buf)
{
    uint64_t sect_start, sect_off;
    uint32_t count = 0;
    struct ata_drive *ata = &ATA_Drv[drv];
    uint32_t buffer_off = 0;
    sect_start = start >> ata->sector_size_shift;
    sect_off = start - (sect_start << ata->sector_size_shift);

    if (sect_off > 0) {
        uint32_t len = MAX_SECTOR_SIZE - sect_off;
        if (len > size)
            len = size;
        ata_cache_pull(drv, sect_start);
        if (ata->cached != sect_start)
            return -1;
        memcpy(buf, ata->sector_cache + sect_off, len);
        size -= len;
        buffer_off += len;
        sect_start++;
    }
    if (size > 0)
        count = size >> ata->sector_size_shift;
    if (count > 0) {
        if (ata_drive_read_sector(drv, sect_start, count, buf + buffer_off) < 0)
            return -1;
        size -= (count << ata->sector_size_shift);
        buffer_off += (count << ata->sector_size_shift);
        sect_start += count;
    }
    if (size > 0) {
        ata_cache_pull(drv, sect_start);
        memcpy(buf + buffer_off, ata->sector_cache, size);
        buffer_off += size;
    }
    return buffer_off;
}

/**
 * @brief This function writes data from the provided buffer to the specified ATA
 * drive starting from the given sector. It handles partial writes and multiple
 * sector transfers.
 *
 * @param[in] drv The index of the ATA drive in the ATA_Drv array.
 * @param[in] start The starting sector number to write to.
 * @param[in] size The size of the data to write in bytes.
 * @param[in] buf The buffer containing the data to write.
 *
 * @return The number of bytes written to the drive, or -1 if an error occurs.
 */
int ata_drive_write(int drv, uint64_t start, uint32_t size,
        const uint8_t *buf)
{
    uint64_t sect_start, sect_off;
    uint32_t count;
    struct ata_drive *ata = &ATA_Drv[drv];
    uint32_t buffer_off = 0;
    sect_start = start >> ata->sector_size_shift;
    sect_off = start - (sect_start << ata->sector_size_shift);

    if (sect_off > 0) {
        uint32_t len = MAX_SECTOR_SIZE - sect_off;
        if (len > size)
            len = size;
        ata_cache_pull(drv, sect_start);
        if (ata->cached != sect_start)
            return -1;
        memcpy(ata->sector_cache + sect_off, buf, len);
        ata_cache_commit(drv);
        size -= len;
        buffer_off += len;
        sect_start++;
    }
    if (size > 0)
        count = size >> ata->sector_size_shift;
    if (count > 0) {
        if (ata_drive_write_sector(drv, sect_start, count, buf + buffer_off) < 0)
            return -1;
        size -= (count << ata->sector_size_shift);
        buffer_off += (count << ata->sector_size_shift);
        sect_start += count;
    }
    if (size > 0) {
        ata_cache_pull(drv, sect_start);
        memcpy(ata->sector_cache, buf + buffer_off, size);
        ata_cache_commit(drv);
        buffer_off += size;
    }
    return buffer_off;
}
#endif /* ATA_C */
