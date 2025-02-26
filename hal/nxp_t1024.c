/* nxp_t1024.c
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
 */
#include <stdint.h>
#include "target.h"
#include "printf.h"
#include "string.h"
#include "hal.h"
#include "nxp_ppc.h"

/* Tested on T1024E Rev 1.0, e5500 core 2.1, PVR 8024_1021 and SVR 8548_0010 */
/* IFC: CS0 NOR, CS1 MRAM, CS2 CPLD, CS3, MPU CPLD */
/* DDR: DDR4 w/ECC (5 chips MT40A256M16GE-083EIT) - SPD on I2C1 at Addr 0x51 */

/* Debugging */
/* #define DEBUG_FLASH */
/* #define DEBUG_ESPI 1 */

#define ENABLE_DDR
#define ENABLE_BUS_CLK_CALC
#define ENABLE_IFC
#ifndef BUILD_LOADER_STAGE1
    /* Tests */
    #if 0
        #define TEST_DDR
        #define TEST_FLASH
        #define TEST_TPM
    #endif

    //#define ENABLE_CPLD
    #define ENABLE_QE   /* QUICC Engine */
    //#define ENABLE_FMAN
    //#define ENABLE_MP   /* multi-core support */
    #if defined(WOLFBOOT_TPM) || defined(TEST_TPM)
        #define ENABLE_ESPI /* SPI for TPM */
    #endif
#endif

#define USE_ERRATA_DDRA008378
#define USE_ERRATA_DDRA008109
#define USE_ERRATA_DDRA009663
#define USE_ERRATA_DDRA009942

/* Foward declarations */
#if defined(ENABLE_DDR) && defined(TEST_DDR)
static int test_ddr(void);
#endif
#if defined(ENABLE_IFC) && defined(TEST_FLASH)
static int test_flash(void);
#endif
#if defined(ENABLE_ESPI) && defined(TEST_TPM)
static int test_tpm(void);
#endif

static void hal_flash_unlock_sector(uint32_t sector);

#ifdef ENABLE_ESPI
#include "spi_drv.h" /* for transfer flags and chip select */
#endif

/* T1024 */
#define SYS_CLK (100000000) /* 100MHz */

/* Boot page translation register - T1024RM 4.5.9 */
#define LCC_BSTRH            ((volatile uint32_t*)(CCSRBAR + 0x20)) /* Boot space translation register high */
#define LCC_BSTRL            ((volatile uint32_t*)(CCSRBAR + 0x24)) /* Boot space translation register low */
#define LCC_BSTAR            ((volatile uint32_t*)(CCSRBAR + 0x28)) /* Boot space translation attribute register */
#define LCC_BSTAR_EN         0x80000000
#define LCC_BSTAR_LAWTRGT(n) ((n) << 20)
#define LCC_BSTAR_LAWSZ(n)   ((n) & 0x3F)

/* DCFG (Device Configuration/Pin Control) T1024RM 7.3 */
#define DCFG_BASE      (CCSRBAR + 0xE0000)
#define DCFG_PVR       ((volatile uint32_t*)(DCFG_BASE + 0xA0UL))
#define DCFG_SVR       ((volatile uint32_t*)(DCFG_BASE + 0xA4UL))
#define DCFG_DEVDISR1  ((volatile uint32_t*)(DCFG_BASE + 0x70UL)) /* Device disable register */
#define DCFG_DEVDISR2  ((volatile uint32_t*)(DCFG_BASE + 0x74UL)) /* Device disable register */
#define DCFG_DEVDISR3  ((volatile uint32_t*)(DCFG_BASE + 0x78UL)) /* Device disable register */
#define DCFG_DEVDISR4  ((volatile uint32_t*)(DCFG_BASE + 0x7CUL)) /* Device disable register */
#define DCFG_DEVDISR5  ((volatile uint32_t*)(DCFG_BASE + 0x80UL)) /* Device disable register */
#define DCFG_COREDISR  ((volatile uint32_t*)(DCFG_BASE + 0x94UL)) /* Core Enable/Disable */
#define DCFG_BRR       ((volatile uint32_t*)(DCFG_BASE + 0xE4UL))  /* Boot Release Register (DCFG_CCSR_BRR) */
#define DCFG_DCSR      ((volatile uint32_t*)(DCFG_BASE + 0x704UL)) /* Debug configuration and status */

/* T1024RM: 4.6.5 */
#define CLOCKING_BASE    (CCSRBAR + 0xE1000)
#define CLOCKING_PLLPGSR ((volatile uint32_t*)(CLOCKING_BASE + 0xC00UL)) /* Platform PLL general status register */

#define RCPM_BASE       (CCSRBAR + 0xE2000)
#define RCPM_PCTBENR    ((volatile uint32_t*)(RCPM_BASE + 0x1A0)) /* Physical Core Time Base Enable Bit 0=Core 0 */
#define RCPM_PCTBCKSELR ((volatile uint32_t*)(RCPM_BASE + 0x1A4)) /* Physical Core Time Base Clock Select 0=Platform Clock/16, 1=RTC */
#define RCPM_TBCLKDIVR  ((volatile uint32_t*)(RCPM_BASE + 0x1A8)) /* Time Base Clock Divider 0=1/16, 1=1/8, 2=1/24, 3=1/32 */

/* MPIC - T1024RM 24.3 */
#define PIC_BASE    (CCSRBAR + 0x40000)
#define PIC_WHOAMI  ((volatile uint32_t*)(PIC_BASE + 0x0090UL)) /* Returns the ID of the processor core reading this register */
#define PIC_GCR     ((volatile uint32_t*)(PIC_BASE + 0x1020UL)) /* Global configuration register (controls PIC operating mode) */
#define PIC_GCR_RST 0x80000000
#define PIC_GCR_M   0x20000000


/* QUICC Engine */
#define QE_MAX_RISC  1

/* QE microcode/firmware address */
#ifndef QE_FW_ADDR
#define QE_FW_ADDR   0xEFE00000 /* location in NOR flash */
#endif

#define QE_BASE                (CCSRBAR + 0xF000)
#define QE_CEPIER              ((volatile uint32_t*)(QE_BASE + 0x00CUL))
#define QE_CEPIMR              ((volatile uint32_t*)(QE_BASE + 0x010UL))
#define QE_CEPICR              ((volatile uint32_t*)(QE_BASE + 0x014UL))

#define QE_ENGINE_BASE         (CCSRBAR + 0x80000)
#define QE_IRAM                (QE_ENGINE_BASE + 0x000UL) /* Instruction RAM registers */
#define QE_IRAM_IADD           ((volatile uint32_t*)(QE_IRAM + 0x000UL))
#define QE_IRAM_IDATA          ((volatile uint32_t*)(QE_IRAM + 0x004UL))
#define QE_IRAM_IREADY         ((volatile uint32_t*)(QE_IRAM + 0x00CUL))

#define QE_CP                  (QE_ENGINE_BASE + 0x100UL)  /* Configuration register */
#define QE_CP_CECR             ((volatile uint32_t*)(QE_CP + 0x00)) /* command register */
#define QE_CP_CECDR            ((volatile uint32_t*)(QE_CP + 0x08)) /* data register */
#define QE_CP_CERCR            ((volatile uint16_t*)(QE_CP + 0x38)) /* RAM control register */

#define QE_SDMA                (QE_ENGINE_BASE + 0x4000UL) /* Serial DMA */
#define QE_SDMA_SDSR           ((volatile uint32_t*)(QE_SDMA + 0x00))
#define QE_SDMA_SDMR           ((volatile uint32_t*)(QE_SDMA + 0x04))
#define QE_SDMA_SDAQR          ((volatile uint32_t*)(QE_SDMA + 0x38))
#define QE_SDMA_SDAQMR         ((volatile uint32_t*)(QE_SDMA + 0x3C))
#define QE_SDMA_SDEBCR         ((volatile uint32_t*)(QE_SDMA + 0x44))

#define QE_RSP                 (QE_ENGINE_BASE + 0x4100UL) /* Special Registers */
#define QE_RSP_TIBCR(n, i)     ((volatile uint32_t*)(QE_RSP + ((n) * 0x100) + (i)))
#define QE_RSP_ECCR(n)         ((volatile uint32_t*)(QE_RSP + ((n) * 0x100) + 0xF0))

#define QE_IRAM_IADD_AIE       0x80000000 /* Auto Increment Enable */
#define QE_IRAM_IADD_BADDR     0x00080000 /* Base Address */
#define QE_IRAM_READY          0x80000000

#define QE_CP_CERCR_CIR        0x0800 /* Common instruction RAM */

#define QE_CR_FLG              0x00010000
#define QE_CR_PROTOCOL_SHIFT   6

#define QE_SDMR_GLB_1_MSK      0x80000000
#define QE_SDMR_CEN_SHIFT      13
#define QE_SDEBCR_BA_MASK      0x01FFFFFF

/* QE Commands */
#define QE_RESET               0x80000000


/* T1024RM 10.5.1: Queue Manager (QMan):
 * - QMan block base address: 31_8000h
 * - 512 frame queue (FQ) cache
 * - 2-Kbyte SFDRs
 * - 256 congestion groups
 */

/* T1024RM 10.5.2: Buffer Manager (BMan):
 * - BMan block base address: 31_A000h
 * - 64 buffer pools
 */

/* T1024RM 10.5.4: Security and Encryption Engine (SEC)
  * - SEC block base address: 30_0000h
  * - 2.5 Gbps SEC processing at 400 MHz
  * - Cryptographic Hardware Accelerators (CHAs) include:
  *   - PKHA
  *   - DESA
  *   - AESA
  *   - MDHA
  *   - RNG4
  *   - AFHA
  */

/* T1024RM 10.5.3: Frame Manager (FMan):
  * - FMan block base address: 40_0000h
  * - Four multirate Ethernet MACs, for configuration options refer to SerDes Protocols
  * - Block base addresses are as follows:
  *   - FM1 mEMAC1: 4E_0000h
  *   - FM1 mEMAC2: 4E_2000h
  *   - FM1 mEMAC3: 4E_4000h
  *   - FM1 mEMAC4: 4E_6000h
  * - mEMAC PortIDs (RX/TX):
  *   - mEMAC1: 08h/28h
  *   - mEMAC2: 09h/29h
  *   - mEMAC3: 0Ah/2Ah
  *   - mEMAC4: 0Bh/2Bh
  * - Supports 1 host command and 3 offline ports:
  *   - Host command: 02h
  *   - Offline port 3: 03h
  *   - Offline port 4: 04h
  *   - Offline port 5: 05h
  * - FM1 Dedicated MDIO1: 4F_C000h
  * - FM1 Dedicated MDIO2: 4F_D000h
  * - One FMan Controller complexes
  * - 192-Kbyte internal FMan memory
  * - 32-Kbyte FMan Controller configuration data
  * - Up to 32 Keygen schemes
  * - Up to 8 Policer profiles
  * - Up to 32 entries in FMan DMA command queue
  * - Up to 64 TNUMs
  * - Up to 1 FMan debug flows
  */

#define FMAN_COUNT 1

#ifndef FMAN_FW_ADDR
#define FMAN_FW_ADDR   0xEFF00000 /* location in NOR flash */
#endif

#define FMAN_BASE              (CCSRBAR + 0x400000)
//#define QE_CEPIER              ((volatile uint32_t*)(FMAN_BASE + 0x00CUL))



/* T1024 PC16552D Dual UART */
#define BAUD_RATE 115200
#define UART_SEL 0 /* select UART 0 or 1 */

#define UART_BASE(n) (CCSRBAR + 0x11C500 + (n * 0x1000))

#define UART_RBR(n)  ((volatile uint8_t*)(UART_BASE(n) + 0)) /* receiver buffer register */
#define UART_THR(n)  ((volatile uint8_t*)(UART_BASE(n) + 0)) /* transmitter holding register */
#define UART_IER(n)  ((volatile uint8_t*)(UART_BASE(n) + 1)) /* interrupt enable register */
#define UART_IIR(n)  ((volatile uint8_t*)(UART_BASE(n) + 2)) /* interrupt ID register */
#define UART_FCR(n)  ((volatile uint8_t*)(UART_BASE(n) + 2)) /* FIFO control register */
#define UART_LCR(n)  ((volatile uint8_t*)(UART_BASE(n) + 3)) /* line control register */
#define UART_MCR(n)  ((volatile uint8_t*)(UART_BASE(n) + 4)) /* modem control register */
#define UART_LSR(n)  ((volatile uint8_t*)(UART_BASE(n) + 5)) /* line status register */

/* enabled when UART_LCR_DLAB set */
#define UART_DLB(n)  ((volatile uint8_t*)(UART_BASE(n) + 0)) /* divisor least significant byte register */
#define UART_DMB(n)  ((volatile uint8_t*)(UART_BASE(n) + 1)) /* divisor most significant byte register */

#define UART_FCR_TFR  (0x04) /* Transmitter FIFO reset */
#define UART_FCR_RFR  (0x02) /* Receiver FIFO reset */
#define UART_FCR_FEN  (0x01) /* FIFO enable */
#define UART_LCR_DLAB (0x80) /* Divisor latch access bit */
#define UART_LCR_WLS  (0x03) /* Word length select: 8-bits */
#define UART_LSR_TEMT (0x40) /* Transmitter empty */
#define UART_LSR_THRE (0x20) /* Transmitter holding register empty */


/* T1024 IFC (Integrated Flash Controller) - RM 23.1 */
#define IFC_BASE        (CCSRBAR + 0x00124000)
#define IFC_MAX_BANKS   8

#define IFC_CSPR_EXT(n) ((volatile uint32_t*)(IFC_BASE + 0x000C + (n * 0xC))) /* Extended Base Address */
#define IFC_CSPR(n)     ((volatile uint32_t*)(IFC_BASE + 0x0010 + (n * 0xC))) /* Chip-select Property */
#define IFC_AMASK(n)    ((volatile uint32_t*)(IFC_BASE + 0x00A0 + (n * 0xC)))
#define IFC_CSOR(n)     ((volatile uint32_t*)(IFC_BASE + 0x0130 + (n * 0xC)))
#define IFC_CSOR_EXT(n) ((volatile uint32_t*)(IFC_BASE + 0x0134 + (n * 0xC)))
#define IFC_FTIM0(n)    ((volatile uint32_t*)(IFC_BASE + 0x01C0 + (n * 0x30)))
#define IFC_FTIM1(n)    ((volatile uint32_t*)(IFC_BASE + 0x01C4 + (n * 0x30)))
#define IFC_FTIM2(n)    ((volatile uint32_t*)(IFC_BASE + 0x01C8 + (n * 0x30)))
#define IFC_FTIM3(n)    ((volatile uint32_t*)(IFC_BASE + 0x01CC + (n * 0x30)))

#define IFC_CSPR_PHYS_ADDR(x) (((uint32_t)x) & 0xFFFFFF00) /* Physical base address */
#define IFC_CSPR_PORT_SIZE_8  0x00000080 /* Port Size 8 */
#define IFC_CSPR_PORT_SIZE_16 0x00000100 /* Port Size 16 */
#define IFC_CSPR_WP           0x00000040 /* Write Protect */
#define IFC_CSPR_MSEL_NOR     0x00000000 /* Mode Select - NOR */
#define IFC_CSPR_MSEL_NAND    0x00000002 /* Mode Select - NAND */
#define IFC_CSPR_MSEL_GPCM    0x00000004 /* Mode Select - GPCM (General-purpose chip-select machine) */
#define IFC_CSPR_V            0x00000001 /* Bank Valid */

/* NOR Timings (IFC clocks) */
#define IFC_FTIM0_NOR_TACSE(n) (((n) & 0x0F) << 28) /* After address hold cycle */
#define IFC_FTIM0_NOR_TEADC(n) (((n) & 0x3F) << 16) /* External latch address delay cycles */
#define IFC_FTIM0_NOR_TAVDS(n) (((n) & 0x3F) << 8)  /* Delay between CS assertion */
#define IFC_FTIM0_NOR_TEAHC(n) (((n) & 0x3F) << 0)  /* External latch address hold cycles */
#define IFC_FTIM1_NOR_TACO(n)  (((n) & 0xFF) << 24) /* CS assertion to output enable */
#define IFC_FTIM1_NOR_TRAD(n)  (((n) & 0x3F) << 8)  /* read access delay */
#define IFC_FTIM1_NOR_TSEQ(n)  (((n) & 0x3F) << 0)  /* sequential read access delay */
#define IFC_FTIM2_NOR_TCS(n)   (((n) & 0x0F) << 24) /* Chip-select assertion setup time */
#define IFC_FTIM2_NOR_TCH(n)   (((n) & 0x0F) << 18) /* Chip-select hold time */
#define IFC_FTIM2_NOR_TWPH(n)  (((n) & 0x3F) << 10) /* Chip-select hold time */
#define IFC_FTIM2_NOR_TWP(n)   (((n) & 0xFF) << 0)  /* Write enable pulse width */

/* GPCM Timings (IFC clocks) */
#define IFC_FTIM0_GPCM_TACSE(n) (((n) & 0x0F) << 28) /* After address hold cycle */
#define IFC_FTIM0_GPCM_TEADC(n) (((n) & 0x3F) << 16) /* External latch address delay cycles */
#define IFC_FTIM0_GPCM_TEAHC(n) (((n) & 0x3F) << 0)  /* External latch address hold cycles */
#define IFC_FTIM1_GPCM_TACO(n)  (((n) & 0xFF) << 24) /* CS assertion to output enable */
#define IFC_FTIM1_GPCM_TRAD(n)  (((n) & 0x3F) << 8)  /* read access delay */
#define IFC_FTIM2_GPCM_TCS(n)   (((n) & 0x0F) << 24) /* Chip-select assertion setup time */
#define IFC_FTIM2_GPCM_TCH(n)   (((n) & 0x0F) << 18) /* Chip-select hold time */
#define IFC_FTIM2_GPCM_TWP(n)   (((n) & 0xFF) << 0)  /* Write enable pulse width */

/* IFC AMASK - RM Table 13-3 - Count of MSB minus 1 */
enum ifc_amask_sizes {
    IFC_AMASK_64KB =  0xFFFF,
    IFC_AMASK_128KB = 0xFFFE,
    IFC_AMASK_256KB = 0xFFFC,
    IFC_AMASK_512KB = 0xFFF8,
    IFC_AMASK_1MB   = 0xFFF0,
    IFC_AMASK_2MB   = 0xFFE0,
    IFC_AMASK_4MB   = 0xFFC0,
    IFC_AMASK_8MB   = 0xFF80,
    IFC_AMASK_16MB  = 0xFF00,
    IFC_AMASK_32MB  = 0xFE00,
    IFC_AMASK_64MB  = 0xFC00,
    IFC_AMASK_128MB = 0xF800,
    IFC_AMASK_256MB = 0xF000,
    IFC_AMASK_512MB = 0xE000,
    IFC_AMASK_1GB   = 0xC000,
    IFC_AMASK_2GB   = 0x8000,
    IFC_AMASK_4GB   = 0x0000,
};

/* NOR Flash */
#define FLASH_BANK_SIZE   (64*1024*1024)
#define FLASH_PAGE_SIZE   (1024) /* program buffer */
#define FLASH_SECTOR_SIZE (128*1024)
#define FLASH_SECTORS     (FLASH_BANK_SIZE / FLASH_SECTOR_SIZE)
#define FLASH_CFI_WIDTH   16 /* 8 or 16 */

#define FLASH_ERASE_TOUT  60000 /* Flash Erase Timeout (ms) */
#define FLASH_WRITE_TOUT  500   /* Flash Write Timeout (ms) */

/* Intel CFI */
#define FLASH_CMD_CFI                  0x98
#define FLASH_CMD_READ_ID              0x90
#define FLASH_CMD_RESET                0xFF
#define FLASH_CMD_BLOCK_ERASE          0x20
#define FLASH_CMD_ERASE_CONFIRM        0xD0
#define FLASH_CMD_WRITE                0x40
#define FLASH_CMD_PROTECT              0x60
#define FLASH_CMD_SETUP                0x60
#define FLASH_CMD_SET_CR_CONFIRM       0x03
#define FLASH_CMD_PROTECT_SET          0x01
#define FLASH_CMD_PROTECT_CLEAR        0xD0
#define FLASH_CMD_CLEAR_STATUS         0x50
#define FLASH_CMD_READ_STATUS          0x70
#define FLASH_CMD_WRITE_TO_BUFFER      0xE8
#define FLASH_CMD_WRITE_BUFFER_PROG    0xE9
#define FLASH_CMD_WRITE_BUFFER_CONFIRM 0xD0

#define FLASH_STATUS_DONE    0x80
#define FLASH_STATUS_ESS     0x40
#define FLASH_STATUS_ECLBS   0x20
#define FLASH_STATUS_PSLBS   0x10
#define FLASH_STATUS_VPENS   0x08
#define FLASH_STATUS_PSS     0x04
#define FLASH_STATUS_DPS     0x02
#define FLASH_STATUS_R       0x01
#define FLASH_STATUS_PROTECT 0x01

/* AMD CFI */
#define AMD_CMD_RESET                0xF0
#define AMD_CMD_WRITE                0xA0
#define AMD_CMD_ERASE_START          0x80
#define AMD_CMD_ERASE_SECTOR         0x30
#define AMD_CMD_UNLOCK_START         0xAA
#define AMD_CMD_UNLOCK_ACK           0x55
#define AMD_CMD_WRITE_TO_BUFFER      0x25
#define AMD_CMD_WRITE_BUFFER_CONFIRM 0x29
#define AMD_CMD_SET_PPB_ENTRY        0xC0
#define AMD_CMD_SET_PPB_EXIT_BC1     0x90
#define AMD_CMD_SET_PPB_EXIT_BC2     0x00
#define AMD_CMD_PPB_UNLOCK_BC1       0x80
#define AMD_CMD_PPB_UNLOCK_BC2       0x30
#define AMD_CMD_PPB_LOCK_BC1         0xA0
#define AMD_CMD_PPB_LOCK_BC2         0x00

#define AMD_STATUS_TOGGLE            0x40
#define AMD_STATUS_ERROR             0x20

/* Flash unlock addresses */
#if FLASH_CFI_WIDTH == 16
#define FLASH_UNLOCK_ADDR1 0x555
#define FLASH_UNLOCK_ADDR2 0x2AA
#else
#define FLASH_UNLOCK_ADDR1 0xAAA
#define FLASH_UNLOCK_ADDR2 0x555
#endif

/* Flash IO Helpers */
#if FLASH_CFI_WIDTH == 16
#define FLASH_IO8_WRITE(sec, n, val)      *((volatile uint16_t*)(FLASH_BASE_ADDR + (FLASH_SECTOR_SIZE * (sec)) + ((n) * 2))) = (((val) << 8) | (val))
#define FLASH_IO16_WRITE(sec, n, val)     *((volatile uint16_t*)(FLASH_BASE_ADDR + (FLASH_SECTOR_SIZE * (sec)) + ((n) * 2))) = (val)
#define FLASH_IO8_READ(sec, n)  (uint8_t)(*((volatile uint16_t*)(FLASH_BASE_ADDR + (FLASH_SECTOR_SIZE * (sec)) + ((n) * 2))))
#define FLASH_IO16_READ(sec, n)           *((volatile uint16_t*)(FLASH_BASE_ADDR + (FLASH_SECTOR_SIZE * (sec)) + ((n) * 2)))
#else
#define FLASH_IO8_WRITE(sec, n, val)      *((volatile uint8_t*)(FLASH_BASE_ADDR  + (FLASH_SECTOR_SIZE * (sec)) + (n))) = (val)
#define FLASH_IO8_READ(sec, n)            *((volatile uint8_t*)(FLASH_BASE_ADDR  + (FLASH_SECTOR_SIZE * (sec)) + (n)))
#endif


/* CPLD */
#define CPLD_BASE               0xFFDF0000
#define CPLD_BASE_PHYS_HIGH     0xFULL

#define CPLD_VER        0x00 /* CPLD Major Revision Register */
#define CPLD_VER_SUB    0x01 /* CPLD Minor Revision Register */
#define HW_VER          0x02 /* Hardware Revision Register */
#define SW_VER          0x03 /* Software Revision register */
#define RESET_CTL1      0x10 /* Reset control Register1 */
#define RESET_CTL2      0x11 /* Reset control Register2 */
#define INT_STATUS      0x12 /* Interrupt status Register */
#define FLASH_CSR       0x13 /* Flash control and status register */
#define FAN_CTL_STATUS  0x14 /* Fan control and status register  */
#define LED_CTL_STATUS  0x15 /* LED control and status register */
#define SFP_CTL_STATUS  0x16 /* SFP control and status register  */
#define MISC_CTL_STATUS 0x17 /* Miscellanies ctrl & status register*/
#define BOOT_OVERRIDE   0x18 /* Boot override register */
#define BOOT_CONFIG1    0x19 /* Boot config override register*/
#define BOOT_CONFIG2    0x1A /* Boot config override register*/

#define CPLD_LBMAP_MASK       0x3F
#define CPLD_BANK_SEL_MASK    0x07
#define CPLD_BANK_OVERRIDE    0x40
#define CPLD_LBMAP_ALTBANK    0x44 /* BANK OR | BANK 4 */
#define CPLD_LBMAP_DFLTBANK   0x40 /* BANK OR | BANK 0 */
#define CPLD_LBMAP_RESET      0xFF
#define CPLD_LBMAP_SHIFT      0x03
#define CPLD_BOOT_SEL         0x80

#define CPLD_PCIE_SGMII_MUX   0x80
#define CPLD_OVERRIDE_BOOT_EN 0x01
#define CPLD_OVERRIDE_MUX_EN  0x02 /* PCIE/2.5G-SGMII mux override enable */

#define CPLD_DATA(n) ((volatile uint8_t*)(CPLD_BASE + n))


/* DDR4 - 2GB */
/* 1600 MT/s (64-bit, CL=12, ECC on) */
#define DDR_CS0_BNDS_VAL       0x0000007F
#define DDR_CS1_BNDS_VAL       0x008000BF
#define DDR_CS2_BNDS_VAL       0x0100013F
#define DDR_CS3_BNDS_VAL       0x0140017F
#define DDR_CS0_CONFIG_VAL     0x80010312
#define DDR_CS1_CONFIG_VAL     0x00000202
#define DDR_CS2_CONFIG_VAL     0x00000202
#define DDR_CS3_CONFIG_VAL     0x00010202
#define DDR_CS_CONFIG_2_VAL    0x00000000

#define DDR_TIMING_CFG_0_VAL   0x8055000C
#define DDR_TIMING_CFG_1_VAL   0x2E268E44
#define DDR_TIMING_CFG_2_VAL   0x0049111C
#define DDR_TIMING_CFG_3_VAL   0x114C1000

#define DDR_TIMING_CFG_4_VAL   0x00220001
#define DDR_TIMING_CFG_5_VAL   0x05401400
#define DDR_TIMING_CFG_8_VAL   0x03115800

#define DDR_SDRAM_MODE_VAL     0x01010215
#define DDR_SDRAM_MODE_2_VAL   0x00000000
#define DDR_SDRAM_MODE_9_VAL   0x00000500 /* Extended SDRAM mode 5 */
#define DDR_SDRAM_MODE_10_VAL  0x04000000 /* Extended SDRAM mode 7 */
#define DDR_SDRAM_MODE_3_8_VAL 0x00000000
#define DDR_SDRAM_MD_CNTL_VAL  0x03001000

#define DDR_SDRAM_CFG_VAL      0xE5200000 /* DDR4 w/ECC */
#define DDR_SDRAM_CFG_2_VAL    0x00401050

#define DDR_SDRAM_INTERVAL_VAL 0x18600618
#define DDR_DATA_INIT_VAL      0xDEADBEEF
#define DDR_SDRAM_CLK_CNTL_VAL 0x02400000
#define DDR_ZQ_CNTL_VAL        0x8A090705

#define DDR_WRLVL_CNTL_VAL     0x8675F606
#define DDR_WRLVL_CNTL_2_VAL   0x06070709
#define DDR_WRLVL_CNTL_3_VAL   0x09090908

#define DDR_SDRAM_RCW_1_VAL    0x00000000
#define DDR_SDRAM_RCW_2_VAL    0x00000000

#define DDR_DDRCDR_1_VAL       0x80080000
#define DDR_DDRCDR_2_VAL       0x00000000

#define DDR_ERR_INT_EN_VAL     0x0000001D
#define DDR_ERR_SBE_VAL        0x00000000


/* 12.4 DDR Memory Map */
#define DDR_BASE           (CCSRBAR + 0x8000)

#define DDR_CS_BNDS(n)     ((volatile uint32_t*)(DDR_BASE + 0x000 + (n * 8))) /* Chip select n memory bounds */
#define DDR_CS_CONFIG(n)   ((volatile uint32_t*)(DDR_BASE + 0x080 + (n * 4))) /* Chip select n configuration */
#define DDR_CS_CONFIG_2(n) ((volatile uint32_t*)(DDR_BASE + 0x0C0 + (n * 4))) /* Chip select n configuration 2 */
#define DDR_SDRAM_CFG      ((volatile uint32_t*)(DDR_BASE + 0x110)) /* DDR SDRAM control configuration */
#define DDR_SDRAM_CFG_2    ((volatile uint32_t*)(DDR_BASE + 0x114)) /* DDR SDRAM control configuration 2 */
#define DDR_SDRAM_CFG_3    ((volatile uint32_t*)(DDR_BASE + 0x260)) /* DDR SDRAM control configuration 3 */
#define DDR_SDRAM_INTERVAL ((volatile uint32_t*)(DDR_BASE + 0x124)) /* DDR SDRAM interval configuration */
#define DDR_INIT_ADDR      ((volatile uint32_t*)(DDR_BASE + 0x148)) /* DDR training initialization address */
#define DDR_INIT_EXT_ADDR  ((volatile uint32_t*)(DDR_BASE + 0x14C)) /* DDR training initialization extended address */
#define DDR_DATA_INIT      ((volatile uint32_t*)(DDR_BASE + 0x128)) /* DDR training initialization value */
#define DDR_TIMING_CFG_0   ((volatile uint32_t*)(DDR_BASE + 0x104)) /* DDR SDRAM timing configuration 0 */
#define DDR_TIMING_CFG_1   ((volatile uint32_t*)(DDR_BASE + 0x108)) /* DDR SDRAM timing configuration 1 */
#define DDR_TIMING_CFG_2   ((volatile uint32_t*)(DDR_BASE + 0x10C)) /* DDR SDRAM timing configuration 2 */
#define DDR_TIMING_CFG_3   ((volatile uint32_t*)(DDR_BASE + 0x100)) /* DDR SDRAM timing configuration 3 */
#define DDR_TIMING_CFG_4   ((volatile uint32_t*)(DDR_BASE + 0x160)) /* DDR SDRAM timing configuration 4 */
#define DDR_TIMING_CFG_5   ((volatile uint32_t*)(DDR_BASE + 0x164)) /* DDR SDRAM timing configuration 5 */
#define DDR_TIMING_CFG_6   ((volatile uint32_t*)(DDR_BASE + 0x168)) /* DDR SDRAM timing configuration 6 */
#define DDR_TIMING_CFG_7   ((volatile uint32_t*)(DDR_BASE + 0x16C)) /* DDR SDRAM timing configuration 7 */
#define DDR_TIMING_CFG_8   ((volatile uint32_t*)(DDR_BASE + 0x250)) /* DDR SDRAM timing configuration 8 */
#define DDR_ZQ_CNTL        ((volatile uint32_t*)(DDR_BASE + 0x170)) /* DDR ZQ calibration control */
#define DDR_WRLVL_CNTL     ((volatile uint32_t*)(DDR_BASE + 0x174)) /* DDR write leveling control */
#define DDR_WRLVL_CNTL_2   ((volatile uint32_t*)(DDR_BASE + 0x190)) /* DDR write leveling control 2 */
#define DDR_WRLVL_CNTL_3   ((volatile uint32_t*)(DDR_BASE + 0x194)) /* DDR write leveling control 3 */
#define DDR_SR_CNTR        ((volatile uint32_t*)(DDR_BASE + 0x17C)) /* DDR Self Refresh Counter */
#define DDR_SDRAM_RCW_1    ((volatile uint32_t*)(DDR_BASE + 0x180)) /* DDR Register Control Word 1 */
#define DDR_SDRAM_RCW_2    ((volatile uint32_t*)(DDR_BASE + 0x184)) /* DDR Register Control Word 2 */
#define DDR_SDRAM_RCW_3    ((volatile uint32_t*)(DDR_BASE + 0x1A0)) /* DDR Register Control Word 3 */
#define DDR_SDRAM_RCW_4    ((volatile uint32_t*)(DDR_BASE + 0x1A4)) /* DDR Register Control Word 4 */
#define DDR_SDRAM_RCW_5    ((volatile uint32_t*)(DDR_BASE + 0x1A8)) /* DDR Register Control Word 5 */
#define DDR_SDRAM_RCW_6    ((volatile uint32_t*)(DDR_BASE + 0x1AC)) /* DDR Register Control Word 6 */
#define DDR_DDRCDR_1       ((volatile uint32_t*)(DDR_BASE + 0xB28)) /* DDR Control Driver Register 1 */
#define DDR_DDRCDR_2       ((volatile uint32_t*)(DDR_BASE + 0xB2C)) /* DDR Control Driver Register 2 */
#define DDR_DDRDSR_1       ((volatile uint32_t*)(DDR_BASE + 0xB20)) /* DDR Debug Status Register 1 */
#define DDR_DDRDSR_2       ((volatile uint32_t*)(DDR_BASE + 0xB24)) /* DDR Debug Status Register 2 */
#define DDR_ERR_DISABLE    ((volatile uint32_t*)(DDR_BASE + 0xE44)) /* Memory error disable */
#define DDR_ERR_INT_EN     ((volatile uint32_t*)(DDR_BASE + 0xE48)) /* Memory error interrupt enable */
#define DDR_ERR_SBE        ((volatile uint32_t*)(DDR_BASE + 0xE58)) /* Single-Bit ECC memory error management */
#define DDR_SDRAM_MODE     ((volatile uint32_t*)(DDR_BASE + 0x118)) /* DDR SDRAM mode configuration */
#define DDR_SDRAM_MODE_2   ((volatile uint32_t*)(DDR_BASE + 0x11C)) /* DDR SDRAM mode configuration 2 */
#define DDR_SDRAM_MODE_3   ((volatile uint32_t*)(DDR_BASE + 0x200)) /* DDR SDRAM mode configuration 3 */
#define DDR_SDRAM_MODE_4   ((volatile uint32_t*)(DDR_BASE + 0x204)) /* DDR SDRAM mode configuration 4 */
#define DDR_SDRAM_MODE_5   ((volatile uint32_t*)(DDR_BASE + 0x208)) /* DDR SDRAM mode configuration 5 */
#define DDR_SDRAM_MODE_6   ((volatile uint32_t*)(DDR_BASE + 0x20C)) /* DDR SDRAM mode configuration 6 */
#define DDR_SDRAM_MODE_7   ((volatile uint32_t*)(DDR_BASE + 0x210)) /* DDR SDRAM mode configuration 7 */
#define DDR_SDRAM_MODE_8   ((volatile uint32_t*)(DDR_BASE + 0x214)) /* DDR SDRAM mode configuration 8 */
#define DDR_SDRAM_MODE_9   ((volatile uint32_t*)(DDR_BASE + 0x220)) /* DDR SDRAM mode configuration 9 */
#define DDR_SDRAM_MODE_10  ((volatile uint32_t*)(DDR_BASE + 0x224)) /* DDR SDRAM mode configuration 10 */
#define DDR_SDRAM_MD_CNTL  ((volatile uint32_t*)(DDR_BASE + 0x120)) /* DDR SDRAM mode control */
#define DDR_SDRAM_CLK_CNTL ((volatile uint32_t*)(DDR_BASE + 0x130)) /* DDR SDRAM clock control */

#define DDR_DEBUG_9        ((volatile uint32_t*)(DDR_BASE + 0xF20))
#define DDR_DEBUG_10       ((volatile uint32_t*)(DDR_BASE + 0xF24))
#define DDR_DEBUG_11       ((volatile uint32_t*)(DDR_BASE + 0xF28))
#define DDR_DEBUG_12       ((volatile uint32_t*)(DDR_BASE + 0xF2C))
#define DDR_DEBUG_13       ((volatile uint32_t*)(DDR_BASE + 0xF30))
#define DDR_DEBUG_14       ((volatile uint32_t*)(DDR_BASE + 0xF34))
#define DDR_DEBUG_19       ((volatile uint32_t*)(DDR_BASE + 0xF48))
#define DDR_DEBUG_29       ((volatile uint32_t*)(DDR_BASE + 0xF70))

#define DDR_SDRAM_CFG_MEM_EN   0x80000000 /* SDRAM interface logic is enabled */
#define DDR_SDRAM_CFG_ECC_EN   0x20000000
#define DDR_SDRAM_CFG_32_BE    0x00080000
#define DDR_SDRAM_CFG_2_D_INIT 0x00000010 /* data initialization in progress */
#define DDR_SDRAM_CFG_HSE      0x00000008
#define DDR_SDRAM_CFG_BI       0x00000001 /* Bypass initialization */
#define DDR_SDRAM_CFG_SDRAM_TYPE_MASK 0x07000000
#define DDR_SDRAM_CFG_SDRAM_TYPE(n) (((n) & 0x7) << 24)
#define DDR_SDRAM_TYPE_DDR4    5
#define DDR_SDRAM_INTERVAL_BSTOPRE 0x3FFF


/* eSPI */
#define ESPI_MAX_CS_NUM      4
#define ESPI_MAX_RX_LEN      (1 << 16)
#define ESPI_FIFO_WORD       4

#define ESPI_BASE            (CCSRBAR + 0x7000)
#define ESPI_SPMODE          ((volatile uint32_t*)(ESPI_BASE + 0x00)) /* controls eSPI general operation mode */
#define ESPI_SPIE            ((volatile uint32_t*)(ESPI_BASE + 0x04)) /* controls interrupts and report events */
#define ESPI_SPIM            ((volatile uint32_t*)(ESPI_BASE + 0x08)) /* enables/masks interrupts */
#define ESPI_SPCOM           ((volatile uint32_t*)(ESPI_BASE + 0x0C)) /* command frame information */
#define ESPI_SPITF           ((volatile uint32_t*)(ESPI_BASE + 0x10)) /* transmit FIFO access register (32-bit) */
#define ESPI_SPIRF           ((volatile uint32_t*)(ESPI_BASE + 0x14)) /* read-only receive data register (32-bit) */
#define ESPI_SPITF8          ((volatile uint8_t*)( ESPI_BASE + 0x10)) /* transmit FIFO access register (8-bit) */
#define ESPI_SPIRF8          ((volatile uint8_t*)( ESPI_BASE + 0x14)) /* read-only receive data register (8-bit) */
#define ESPI_SPCSMODE(x)     ((volatile uint32_t*)(ESPI_BASE + 0x20 + ((cs) * 4))) /* controls master operation with chip select 0-3 */

#define ESPI_SPMODE_EN       (0x80000000) /* Enable eSPI */
#define ESPI_SPMODE_TXTHR(x) ((x) << 8)   /* Tx FIFO threshold (1-32) */
#define ESPI_SPMODE_RXTHR(x) ((x) << 0)   /* Rx FIFO threshold (0-31) */

#define ESPI_SPCOM_CS(x)     ((x) << 30)       /* Chip select-chip select for which transaction is destined */
#define ESPI_SPCOM_RXSKIP(x) ((x) << 16)       /* Number of characters skipped for reception from frame start */
#define ESPI_SPCOM_TRANLEN(x) (((x) - 1) << 0) /* Transaction length */

#define ESPI_SPIE_TXE        (1 << 15) /* transmit empty */
#define ESPI_SPIE_DON        (1 << 14) /* Last character was transmitted */
#define ESPI_SPIE_RXT        (1 << 13) /* Rx FIFO has more than RXTHR bytes */
#define ESPI_SPIE_RNE        (1 << 9)  /* receive not empty */
#define ESPI_SPIE_TNF        (1 << 8)  /* transmit not full */
#define ESPI_SPIE_RXCNT(n)   (((n) >> 24) & 0x3F) /* The current number of full Rx FIFO bytes */

#define ESPI_CSMODE_CI       0x80000000 /* Inactive high */
#define ESPI_CSMODE_CP       0x40000000 /* Begin edge clock */
#define ESPI_CSMODE_REV      0x20000000 /* MSB first */
#define ESPI_CSMODE_DIV16    0x10000000 /* divide system clock by 16 */
#define ESPI_CSMODE_PM(x)    (((x) & 0xF) << 24) /* presale modulus select */
#define ESPI_CSMODE_POL      0x00100000  /* asserted low */
#define ESPI_CSMODE_LEN(x)   ((((x) - 1) & 0xF) << 16) /* Character length in bits per character */
#define ESPI_CSMODE_CSBEF(x) (((x) & 0xF) << 12) /* CS assertion time in bits before frame start */
#define ESPI_CSMODE_CSAFT(x) (((x) & 0xF) << 8)  /* CS assertion time in bits after frame end */
#define ESPI_CSMODE_CSCG(x)  (((x) & 0xF) << 3)  /* Clock gaps between transmitted frames according to this size */


/* generic share NXP QorIQ driver code */
#include "nxp_ppc.c"


#ifdef ENABLE_BUS_CLK_CALC
static uint32_t hal_get_bus_clk(void)
{
    /* compute bus clock (system input * ratio) */
    uint32_t plat_clk, bus_clk;
    uint32_t plat_ratio = get32(CLOCKING_PLLPGSR); /* see SYS_PLL_RAT in RCW */
    /* mask and shift by 1 to get platform ratio */
    plat_ratio = ((plat_ratio & 0x3E) >> 1); /* default is 4 (4:1) */
    plat_clk = SYS_CLK * plat_ratio;
    bus_clk = plat_clk / 2;
    return bus_clk;
}
#else
#define hal_get_bus_clk() (uint32_t)((SYS_CLK * 4) / 2)
#endif

#define DELAY_US ((hal_get_bus_clk() / 16) / 1000000)
static void udelay(uint32_t delay_us)
{
    wait_ticks(delay_us * DELAY_US);
}

static void law_init(void)
{
    /* Buffer Manager (BMan) (control) - probably not required */
    set_law(3, 0xF, 0xF4000000, LAW_TRGT_BMAN, LAW_SIZE_32MB, 1);
}


/* ---- eSPI Driver ---- */
#ifdef ENABLE_ESPI
void hal_espi_init(uint32_t cs, uint32_t clock_hz, uint32_t mode)
{
    uint32_t spibrg = hal_get_bus_clk() / 2, pm, csmode;

    /* Enable eSPI with TX threadshold 4 and RX threshold 3 */
    set32(ESPI_SPMODE, (ESPI_SPMODE_EN | ESPI_SPMODE_TXTHR(4) |
        ESPI_SPMODE_RXTHR(3)));

    set32(ESPI_SPIE, 0xffffffff); /* Clear all eSPI events */
    set32(ESPI_SPIM, 0x00000000); /* Mask all eSPI interrupts */

    csmode = (ESPI_CSMODE_REV | ESPI_CSMODE_POL | ESPI_CSMODE_LEN(8) |
        ESPI_CSMODE_CSBEF(0) | ESPI_CSMODE_CSAFT(0) | ESPI_CSMODE_CSCG(1));

    /* calculate clock divisor */
    if (spibrg / clock_hz > 16) {
        csmode |= ESPI_CSMODE_DIV16;
        pm = (spibrg / (clock_hz * 16));
    }
    else {
        pm = (spibrg / (clock_hz));
    }
    if (pm > 0)
        pm--;

    csmode |= ESPI_CSMODE_PM(pm);

    if (mode & 1)
        csmode |= ESPI_CSMODE_CP;
    if (mode & 2)
        csmode |= ESPI_CSMODE_CI;

    /* configure CS */
    set32(ESPI_SPCSMODE(cs), csmode);
}

int hal_espi_xfer(int cs, const uint8_t* tx, uint8_t* rx, uint32_t sz,
    int flags)
{
    uint32_t mosi, miso, xfer, event;

#ifdef DEBUG_ESPI
    wolfBoot_printf("CS %d, Sz %d, Flags %x\n", cs, sz, flags);
#endif

    if (sz > 0) {
        /* assert CS - use max length and control CS with mode enable toggle */
        set32(ESPI_SPCOM, ESPI_SPCOM_CS(cs) | ESPI_SPCOM_TRANLEN(0x10000));
        set32(ESPI_SPIE, 0xffffffff); /* Clear all eSPI events */
    }
    while (sz > 0) {
        xfer = ESPI_FIFO_WORD;
        if (xfer > sz)
            xfer = sz;

        /* Transfer 4 or 1 */
        if (xfer == ESPI_FIFO_WORD) {
            set32(ESPI_SPITF, *((uint32_t*)tx));
        }
        else {
            xfer = 1;
            set8(ESPI_SPITF8, *((uint8_t*)tx));
        }

        /* wait till TX fifo is empty or done */
        while (1) {
            event = get32(ESPI_SPIE);
            if (event & (ESPI_SPIE_TXE | ESPI_SPIE_DON)) {
                /* clear events */
                set32(ESPI_SPIE, (ESPI_SPIE_TXE | ESPI_SPIE_DON));
                break;
            }
        }

        /* wait till RX has enough data */
        while (1) {
            event = get32(ESPI_SPIE);
            if ((event & ESPI_SPIE_RNE) == 0)
                continue;
        #if defined(DEBUG_ESPI) && DEBUG_ESPI > 1
            wolfBoot_printf("event %x\n", event);
        #endif
            if (ESPI_SPIE_RXCNT(event) >= xfer)
                break;
        }
        if (xfer == ESPI_FIFO_WORD) {
            *((uint32_t*)rx) = get32(ESPI_SPIRF);
        }
        else {
            *((uint8_t*)rx) = get8(ESPI_SPIRF8);
        }

#ifdef DEBUG_ESPI
        wolfBoot_printf("MOSI %x, MISO %x\n",
            *((uint32_t*)tx), *((uint32_t*)rx));
#endif
        tx += xfer;
        rx += xfer;
        sz -= xfer;
    }

    if (!(flags & SPI_XFER_FLAG_CONTINUE)) {
        /* toggle ESPI_SPMODE_EN - to deassert CS */
        set32(ESPI_SPMODE, get32(ESPI_SPMODE) & ~ESPI_SPMODE_EN);
        set32(ESPI_SPMODE, get32(ESPI_SPMODE) | ESPI_SPMODE_EN);
    }

    return 0;
}
void hal_espi_deinit(void)
{
    /* do nothing */
}
#endif /* ENABLE_ESPI */

#ifdef DEBUG_UART
void uart_init(void)
{
    /* calc divisor for UART
     * baud rate = CCSRBAR frequency ÷ (16 x [UDMB||UDLB])
     */
    /* compute UART divisor - round up */
    uint32_t div = (hal_get_bus_clk() + (16/2 * BAUD_RATE)) / (16 * BAUD_RATE);

    while (!(get8(UART_LSR(UART_SEL)) & UART_LSR_TEMT))
       ;

    /* set ier, fcr, mcr */
    set8(UART_IER(UART_SEL), 0);
    set8(UART_FCR(UART_SEL), (UART_FCR_TFR | UART_FCR_RFR | UART_FCR_FEN));

    /* enable baud rate access (DLAB=1) - divisor latch access bit*/
    set8(UART_LCR(UART_SEL), (UART_LCR_DLAB | UART_LCR_WLS));
    /* set divisor */
    set8(UART_DLB(UART_SEL), (div & 0xff));
    set8(UART_DMB(UART_SEL), ((div>>8) & 0xff));
    /* disable rate access (DLAB=0) */
    set8(UART_LCR(UART_SEL), (UART_LCR_WLS));
}

void uart_write(const char* buf, uint32_t sz)
{
    uint32_t pos = 0;
    while (sz-- > 0) {
        char c = buf[pos++];
        if (c == '\n') { /* handle CRLF */
            while ((get8(UART_LSR(UART_SEL)) & UART_LSR_THRE) == 0);
            set8(UART_THR(UART_SEL), '\r');
        }
        while ((get8(UART_LSR(UART_SEL)) & UART_LSR_THRE) == 0);
        set8(UART_THR(UART_SEL), c);
    }
}
#endif /* DEBUG_UART */

#if defined(ENABLE_IFC) && !defined(BUILD_LOADER_STAGE1)
static int hal_flash_getid(void)
{
    uint8_t manfid[4];

    hal_flash_unlock_sector(0);
    FLASH_IO8_WRITE(0, FLASH_UNLOCK_ADDR1, FLASH_CMD_READ_ID);
    udelay(1000);

    manfid[0] = FLASH_IO8_READ(0, 0);  /* Manufacture Code */
    manfid[1] = FLASH_IO8_READ(0, 1);  /* Device Code 1 */
    manfid[2] = FLASH_IO8_READ(0, 14); /* Device Code 2 */
    manfid[3] = FLASH_IO8_READ(0, 15); /* Device Code 3 */

    /* Exit read info */
    FLASH_IO8_WRITE(0, 0, AMD_CMD_RESET);
    udelay(1);

    wolfBoot_printf("Flash: Mfg 0x%x, Device Code 0x%x/0x%x/0x%x\n",
        manfid[0], manfid[1], manfid[2], manfid[3]);

    return 0;
}
#endif /* ENABLE_IFC && !BUILD_LOADER_STAGE1 */

static void hal_flash_init(void)
{
#ifdef ENABLE_IFC
    /* IFC - NOR Flash */
    /* LAW is already set in boot_ppc_start.S:flash_law */

    /* NOR IFC Flash Timing Parameters */
    set32(IFC_FTIM0(0), (IFC_FTIM0_NOR_TACSE(4) |
                         IFC_FTIM0_NOR_TEADC(5) |
                         IFC_FTIM0_NOR_TEAHC(5)));
    set32(IFC_FTIM1(0), (IFC_FTIM1_NOR_TACO(53) |
                         IFC_FTIM1_NOR_TRAD(26) |
                         IFC_FTIM1_NOR_TSEQ(19)));
    set32(IFC_FTIM2(0), (IFC_FTIM2_NOR_TCS(4) |
                         IFC_FTIM2_NOR_TCH(4) |
                         IFC_FTIM2_NOR_TWPH(14) |
                         IFC_FTIM2_NOR_TWP(28)));
    set32(IFC_FTIM3(0), 0);
    /* NOR IFC Definitions (CS0) */
    set32(IFC_CSPR_EXT(0), FLASH_BASE_PHYS_HIGH);
    set32(IFC_CSPR(0), (IFC_CSPR_PHYS_ADDR(FLASH_BASE_ADDR) |
                    #if FLASH_CFI_WIDTH == 16
                        IFC_CSPR_PORT_SIZE_16 |
                    #else
                        IFC_CSPR_PORT_SIZE_8 |
                    #endif
                        IFC_CSPR_MSEL_NOR |
                        IFC_CSPR_V));
    set32(IFC_AMASK(0), IFC_AMASK_64MB);
    set32(IFC_CSOR(0),  0x0000000C); /* TRHZ (80 clocks for read enable high) */

    #ifndef BUILD_LOADER_STAGE1
    hal_flash_getid();
    #endif
#endif /* ENABLE_IFC */
}

static void hal_ddr_init(void)
{
#ifdef ENABLE_DDR
    uint32_t reg;

    /* Map LAW for DDR */
    set_law(15, 0, DDR_ADDRESS, LAW_TRGT_DDR_1, LAW_SIZE_2GB, 0);

    /* If DDR is already enabled then just return */
    if ((get32(DDR_SDRAM_CFG) & DDR_SDRAM_CFG_MEM_EN)) {
        return;
    }

    /* Set early for clock / pin */
    set32(DDR_SDRAM_CLK_CNTL, DDR_SDRAM_CLK_CNTL_VAL);

    /* Setup DDR CS (chip select) bounds */
    set32(DDR_CS_BNDS(0), DDR_CS0_BNDS_VAL);
    set32(DDR_CS_CONFIG(0), DDR_CS0_CONFIG_VAL);
    set32(DDR_CS_CONFIG_2(0), DDR_CS_CONFIG_2_VAL);
    set32(DDR_CS_BNDS(1), DDR_CS1_BNDS_VAL);
    set32(DDR_CS_CONFIG(1), DDR_CS1_CONFIG_VAL);
    set32(DDR_CS_CONFIG_2(1), DDR_CS_CONFIG_2_VAL);
    set32(DDR_CS_BNDS(2), DDR_CS2_BNDS_VAL);
    set32(DDR_CS_CONFIG(2), DDR_CS2_CONFIG_VAL);
    set32(DDR_CS_CONFIG_2(2), DDR_CS_CONFIG_2_VAL);
    set32(DDR_CS_BNDS(3), DDR_CS3_BNDS_VAL);
    set32(DDR_CS_CONFIG(3), DDR_CS3_CONFIG_VAL);
    set32(DDR_CS_CONFIG_2(3), DDR_CS_CONFIG_2_VAL);

    /* DDR SDRAM timing configuration */
    set32(DDR_TIMING_CFG_3, DDR_TIMING_CFG_3_VAL);
    set32(DDR_TIMING_CFG_0, DDR_TIMING_CFG_0_VAL);
    set32(DDR_TIMING_CFG_1, DDR_TIMING_CFG_1_VAL);
    set32(DDR_TIMING_CFG_2, DDR_TIMING_CFG_2_VAL);
    set32(DDR_TIMING_CFG_4, DDR_TIMING_CFG_4_VAL);
    set32(DDR_TIMING_CFG_5, DDR_TIMING_CFG_5_VAL);
    set32(DDR_TIMING_CFG_8, DDR_TIMING_CFG_8_VAL);

    set32(DDR_ZQ_CNTL, DDR_ZQ_CNTL_VAL);
    set32(DDR_SDRAM_CFG_3, 0);

    /* DDR SDRAM mode configuration */
    set32(DDR_SDRAM_MODE,   DDR_SDRAM_MODE_VAL);
    set32(DDR_SDRAM_MODE_2, DDR_SDRAM_MODE_2_VAL);
    set32(DDR_SDRAM_MODE_3, DDR_SDRAM_MODE_3_8_VAL);
    set32(DDR_SDRAM_MODE_4, DDR_SDRAM_MODE_3_8_VAL);
    set32(DDR_SDRAM_MODE_5, DDR_SDRAM_MODE_3_8_VAL);
    set32(DDR_SDRAM_MODE_6, DDR_SDRAM_MODE_3_8_VAL);
    set32(DDR_SDRAM_MODE_7, DDR_SDRAM_MODE_3_8_VAL);
    set32(DDR_SDRAM_MODE_8, DDR_SDRAM_MODE_3_8_VAL);
    set32(DDR_SDRAM_MODE_9, DDR_SDRAM_MODE_9_VAL);
    set32(DDR_SDRAM_MODE_10, DDR_SDRAM_MODE_10_VAL);
    set32(DDR_SDRAM_MD_CNTL, DDR_SDRAM_MD_CNTL_VAL);

    /* DDR Configuration */
#ifdef USE_ERRATA_DDRA009663
    /* Errata A-009663 - DRAM VRef training (do not set precharge interval till after enable) */
    set32(DDR_SDRAM_INTERVAL, DDR_SDRAM_INTERVAL_VAL & ~DDR_SDRAM_INTERVAL_BSTOPRE);
#else
    set32(DDR_SDRAM_INTERVAL, DDR_SDRAM_INTERVAL_VAL);
#endif
    set32(DDR_DATA_INIT, DDR_DATA_INIT_VAL);
    set32(DDR_WRLVL_CNTL, DDR_WRLVL_CNTL_VAL);
    set32(DDR_WRLVL_CNTL_2, DDR_WRLVL_CNTL_2_VAL);
    set32(DDR_WRLVL_CNTL_3, DDR_WRLVL_CNTL_3_VAL);
    set32(DDR_SR_CNTR, 0);
    set32(DDR_SDRAM_RCW_1, 0);
    set32(DDR_SDRAM_RCW_2, 0);
    set32(DDR_SDRAM_RCW_3, 0);
    set32(DDR_SDRAM_RCW_4, 0);
    set32(DDR_SDRAM_RCW_5, 0);
    set32(DDR_SDRAM_RCW_6, 0);
    set32(DDR_DDRCDR_1, DDR_DDRCDR_1_VAL);
    set32(DDR_SDRAM_CFG_2, (DDR_SDRAM_CFG_2_VAL | DDR_SDRAM_CFG_2_D_INIT));
    set32(DDR_INIT_ADDR, 0);
    set32(DDR_INIT_EXT_ADDR, 0);
    set32(DDR_DDRCDR_2, DDR_DDRCDR_2_VAL);
    set32(DDR_ERR_DISABLE, 0);
    set32(DDR_ERR_INT_EN, DDR_ERR_INT_EN_VAL);
    set32(DDR_ERR_SBE, DDR_ERR_SBE_VAL);

    /* Set values, but do not enable the DDR yet */
    set32(DDR_SDRAM_CFG, DDR_SDRAM_CFG_VAL & ~DDR_SDRAM_CFG_MEM_EN);
    __asm__ __volatile__("sync;isync");

    /* busy wait for ~500us */
    udelay(500);
    __asm__ __volatile__("sync;isync");

    /* Enable controller */
    reg = get32(DDR_SDRAM_CFG) & ~DDR_SDRAM_CFG_BI;
    set32(DDR_SDRAM_CFG, reg | DDR_SDRAM_CFG_MEM_EN);
    __asm__ __volatile__("sync;isync");

#ifdef USE_ERRATA_DDRA008378
    /* Errata A-008378: training in DDR4 mode */
    /* write to DEBUG_29[8:11] a value of 4'b1001 before controller is enabled */
    reg = get32(DDR_DEBUG_29);
    reg |= (0x9 << 20);
    set32(DDR_DEBUG_29, reg);
#endif
#ifdef USE_ERRATA_DDRA008109
    /* Errata A-008109: Memory controller could fail to complete initialization */
    reg = get32(DDR_SDRAM_CFG_2);
    reg |= 0x800; /* set DDR_SLOW */
    set32(DDR_SDRAM_CFG_2, reg);
    reg = get32(DDR_DEBUG_19);
    reg |= 0x2;
    set32(DDR_DEBUG_19, reg);
    set32(DDR_DEBUG_29, 0x30000000);
#endif
#ifdef USE_ERRATA_DDRA009942
    /* Errata A-009942: DDR controller can train to non-optimal setting */
    reg = get32(DDR_DEBUG_29);
    reg &= ~0xFF0FFF00;
    reg |=  0x0070006F; /* CPO calculated */
    set32(DDR_DEBUG_29, reg);
#endif

    /* Wait for data initialization to complete */
    while (get32(DDR_SDRAM_CFG_2) & DDR_SDRAM_CFG_2_D_INIT) {
        /* busy wait loop - throttle polling */
        udelay(10000);
    }

#ifdef USE_ERRATA_DDRA009663
    /* Errata A-009663 - Write real precharge interval */
    set32(DDR_SDRAM_INTERVAL, DDR_SDRAM_INTERVAL_VAL);
#endif
#endif
}


void hal_early_init(void)
{
    /* enable timebase on core 0 */
    set32(RCPM_PCTBENR, (1 << 0));

    /* invalidate the CPC before DDR gets enabled */
    set32((volatile uint32_t*)(CPC_BASE + CPCCSR0),
        (CPCCSR0_CPCFI | CPCCSR0_CPCLFC));
    while (get32((volatile uint32_t*)(CPC_BASE + CPCCSR0)) &
        (CPCCSR0_CPCFI | CPCCSR0_CPCLFC));

    /* set DCSRCR space = 1G */
    set32(DCFG_DCSR, (get32(DCFG_DCSR) | CORENET_DCSR_SZ_1G));
    get32(DCFG_DCSR); /* read again */

    /* disable devices */
    set32(DCFG_DEVDISR1,
        ((1 << 19) | /* Disable USB1 */
         (1 << 18) | /* Disable USB2 */
         (1 << 15) | /* SATA1 */
         (1 << 2)    /* DIU (LCD) */
    ));

    hal_ddr_init();
}

static void hal_cpld_init(void)
{
#ifdef ENABLE_CPLD
    #ifdef DEBUG
    uint32_t fw;
    #endif
    /* CPLD IFC Timing Parameters */
    set32(IFC_FTIM0(2), (IFC_FTIM0_GPCM_TACSE(14) |
                         IFC_FTIM0_GPCM_TEADC(14) |
                         IFC_FTIM0_GPCM_TEAHC(14)));
    set32(IFC_FTIM1(2), (IFC_FTIM1_GPCM_TACO(14) |
                         IFC_FTIM1_GPCM_TRAD(31)));
    set32(IFC_FTIM2(2), (IFC_FTIM2_GPCM_TCS(14) |
                         IFC_FTIM2_GPCM_TCH(8) |
                         IFC_FTIM2_GPCM_TWP(31)));
    set32(IFC_FTIM3(2), 0);

    /* CPLD IFC Definitions (CS2) */
    set32(IFC_CSPR_EXT(2), CPLD_BASE_PHYS_HIGH);
    set32(IFC_CSPR(2),     (IFC_CSPR_PHYS_ADDR(CPLD_BASE) |
                            IFC_CSPR_PORT_SIZE_8 |
                            IFC_CSPR_MSEL_GPCM |
                            IFC_CSPR_V));
    set32(IFC_AMASK(2), IFC_AMASK_64KB);
    set32(IFC_CSOR(2), 0);

    /* IFC - CPLD */
    set_law(2, CPLD_BASE_PHYS_HIGH, CPLD_BASE,
        LAW_TRGT_IFC, LAW_SIZE_4KB, 1);

    /* CPLD - TBL=1, Entry 11 */
    set_tlb(1, 11, CPLD_BASE, CPLD_BASE, CPLD_BASE_PHYS_HIGH,
        MAS3_SX | MAS3_SW | MAS3_SR, MAS2_I | MAS2_G,
        0, BOOKE_PAGESZ_4K, 1);

#ifdef DEBUG
    fw = get8(CPLD_DATA(HW_VER));
    wolfBoot_printf("CPLD HW Rev: 0x%x\n", fw);
    fw = get8(CPLD_DATA(SW_VER));
    wolfBoot_printf("CPLD SW Rev: 0x%x\n", fw);
#endif
#endif /* ENABLE_CPLD */
}


/* QE Microcode */
#if defined(ENABLE_QE) || defined(ENABLE_FMAN)

/* Structure packing */
#if (defined(__IAR_SYSTEMS_ICC__) && (__IAR_SYSTEMS_ICC__ > 8)) || \
    defined(__GNUC__)
    #define QE_PACKED __attribute__ ((packed))
#else
    #define QE_PACKED
#endif

/* QE based on work from Shlomi Gridish and Dave Liu at Freescale/NXP */

struct qe_header {
    uint32_t length;      /* Length of the entire structure, in bytes */
    uint8_t  magic[3];    /* Set to { 'Q', 'E', 'F' } */
    uint8_t  version;     /* Version of this layout. First ver is '1' */
} QE_PACKED;

struct qe_soc {
    uint16_t model;       /* The SOC model  */
    uint8_t  major;       /* The SOC revision major */
    uint8_t  minor;       /* The SOC revision minor */
} QE_PACKED;

struct qe_microcode {
    uint8_t  id[32];      /* Null-terminated identifier */
    uint32_t traps[16];   /* Trap addresses, 0 == ignore */
    uint32_t eccr;        /* The value for the ECCR register */
    uint32_t iram_offset; /* Offset into I-RAM for the code */
    uint32_t count;       /* Number of 32-bit words of the code */
    uint32_t code_offset; /* Offset of the actual microcode */
    uint8_t  major;       /* The microcode version major */
    uint8_t  minor;       /* The microcode version minor */
    uint8_t  revision;    /* The microcode version revision */
    uint8_t  padding;     /* Reserved, for alignment */
    uint8_t  reserved[4]; /* Reserved, for future expansion */
} QE_PACKED;

struct qe_firmware {
    struct qe_header    header;
    uint8_t             id[62];         /* Null-terminated identifier string */
    uint8_t             split;          /* 0 = shared I-RAM, 1 = split I-RAM */
    uint8_t             count;          /* Number of microcode[] structures */
    struct qe_soc       soc;
    uint8_t             padding[4];     /* Reserved, for alignment */
    uint64_t            extended_modes; /* Extended modes */
    uint32_t            vtraps[8];      /* Virtual trap addresses */
    uint8_t             reserved[4];    /* Reserved, for future expansion */
    struct qe_microcode microcode[1];
    /* All microcode binaries should be located here */
    /* CRC32 should be located here, after the microcode binaries */
} QE_PACKED;

static void qe_upload_microcode(const struct qe_firmware *firmware,
    const struct qe_microcode *ucode)
{
    const uint32_t *code = (void*)firmware + ucode->code_offset;
    unsigned int i;

    wolfBoot_printf("QE: uploading '%s' version %u.%u.%u\n",
        ucode->id, ucode->major, ucode->minor, ucode->revision);

    /* Use auto-increment */
    set32(QE_IRAM_IADD, ucode->iram_offset |
        QE_IRAM_IADD_AIE | QE_IRAM_IADD_BADDR);

    /* Copy 32-bits at a time to iRAM */
    for (i = 0; i < ucode->count; i++) {
        set32(QE_IRAM_IDATA, code[i]);
    }
}

/* Upload a microcode to the I-RAM at a specific address */
static int qe_upload_firmware(const struct qe_firmware *firmware)
{
    unsigned int i, j;
    uint32_t crc;
    size_t calc_size = sizeof(struct qe_firmware);
    size_t length;
    const struct qe_header *hdr;

    hdr = &firmware->header;
    length = hdr->length;

    /* Check the magic */
    if ((hdr->magic[0] != 'Q') || (hdr->magic[1] != 'E') ||
        (hdr->magic[2] != 'F')) {
        wolfBoot_printf("QE firmware header invalid!\n");
        return -1;
    }

    /* Check the version */
    if (hdr->version != 1) {
        wolfBoot_printf("QE version %d unsupported!\n", hdr->version);
        return -1;
    }

    /* Validate some of the fields */
    if ((firmware->count < 1) || (firmware->count > QE_MAX_RISC)) {
        wolfBoot_printf("QE count %d invalid!\n", firmware->count);
        return -1;
    }

    /* Validate the length and check if there's a CRC */
    calc_size += (firmware->count - 1) * sizeof(struct qe_microcode);
    for (i = 0; i < firmware->count; i++) {
        /* For situations where the second RISC uses the same microcode
         * as the first, the 'code_offset' and 'count' fields will be
         * zero, so it's okay to add those. */
        calc_size += sizeof(uint32_t) * firmware->microcode[i].count;
    }

    /* Validate the length */
    if (length != calc_size + sizeof(uint32_t)) {
        wolfBoot_printf("QE length %d invalid!\n", length);
        return -1;
    }

#ifdef ENABLE_QE_CRC32
    /* Validate the CRC */
    crc = *(uint32_t *)((void *)firmware + calc_size);
    if (crc != (crc32(-1, (const void *) firmware, calc_size) ^ -1)) {
        wolfBoot_printf("QE firmware CRC is invalid\n");
        return -1;
    }
#endif

    /* Use common instruction RAM if not split (default is split) */
    if (!firmware->split) {
        set16(QE_CP_CERCR, get16(QE_CP_CERCR) | QE_CP_CERCR_CIR);
    }

    wolfBoot_printf("QE: Length %d, Count %d\n", length, firmware->count);

    /* Loop through each microcode. */
    for (i = 0; i < firmware->count; i++) {
        const struct qe_microcode *ucode = &firmware->microcode[i];
        uint32_t trapCount = 0;

        /* Upload a microcode if it's present */
        if (ucode->code_offset) {
            qe_upload_microcode(firmware, ucode);
        }

        /* Program the traps for this processor (max 16) */
        for (j = 0; j < 16; j++) {
            uint32_t trap = ucode->traps[j];
            if (trap) {
                trapCount++;
                set32(QE_RSP_TIBCR(i, j), trap);
            }
        }

        /* Enable traps */
        set32(QE_RSP_ECCR(i), ucode->eccr);
        wolfBoot_printf("QE: Traps %d\n", trapCount);
    }

    return 0;
}

#endif

/* ---- QUICC Engine Driver ---- */
#ifdef ENABLE_QE

static void qe_issue_cmd(uint32_t cmd, uint32_t sbc, uint8_t mcn,
    uint32_t cmd_data)
{
    set32(QE_CP_CECDR, cmd_data);
    set32(QE_CP_CECR,
        sbc |       /* sub block code */
        QE_CR_FLG | /* flag: set by software, cleared by hardware */
        ((uint32_t)mcn << QE_CR_PROTOCOL_SHIFT) | /* MCC/QMC channel number */
        cmd         /* opcode (reset sets 0x8000_0000) */
    );

    /* Wait for the command semaphore flag to clear */
    while (get32(QE_CP_CECR) & QE_CR_FLG);
}

static int hal_qe_init(void)
{
    int ret;
    uint32_t sdma_base;

    /* Upload microcode to IRAM */
    ret = qe_upload_firmware((const struct qe_firmware *)QE_FW_ADDR);
    if (ret == 0) {
        /* enable the microcode in IRAM */
        set32(QE_IRAM_IREADY, QE_IRAM_READY);

        /* Serial DMA */
        /* All of DMA transaction in bus 1 */
        set32(QE_SDMA_SDAQR, 0);
        set32(QE_SDMA_SDAQMR, 0);

        /* Allocate 2KB temporary buffer for sdma */
        sdma_base = 0;
        set32(QE_SDMA_SDEBCR, sdma_base & QE_SDEBCR_BA_MASK);

        /* Clear sdma status */
        set32(QE_SDMA_SDSR, 0x03000000);

        /* Enable global mode on bus 1, and 2KB buffer size */
        set32(QE_SDMA_SDMR, QE_SDMR_GLB_1_MSK | (0x3 << QE_SDMR_CEN_SHIFT));

        /* Reset QUICC Engine */
        qe_issue_cmd(QE_RESET, 0, 0, 0);
    }

    return ret;
}
#endif /* ENABLE_QUICC */

#ifdef ENABLE_FMAN
static int hal_fman_init(void)
{
    int ret;

    /* Upload microcode to IRAM */
    ret = qe_upload_firmware((const struct qe_firmware *)FMAN_FW_ADDR);
    if (ret == 0) {

    }
    return ret;
}
#endif /* ENABLE_FMAN */


/* SMP Multi-Processor Driver */
#ifdef ENABLE_MP

/* from boot_ppc_core.S */
extern uint32_t _mp_page_start;
extern uint32_t _spin_table;
extern uint32_t _bootpg_addr;

/* Startup additional cores with spin table and synchronize the timebase */
static void hal_mp_up(uint32_t bootpg)
{
    uint32_t all_cores, active_cores, whoami, bpcr;
    uint8_t *spin_table_addr;
    int timeout = 50, i;

    whoami = get32(PIC_WHOAMI); /* Get current running core number */
    all_cores = ((1 << CPU_NUMCORES) - 1); /* mask of all cores */
    active_cores = (1 << whoami); /* current running cores */

    /* Calculate location of spin table in BPTR */
    spin_table_addr = (uint8_t*)(BOOT_ROM_ADDR +
        ((uint32_t)&_spin_table - (uint32_t)&_mp_page_start));

    wolfBoot_printf("MP: Starting core 2 (spin table %p)\n",
        spin_table_addr);

    /* Set the boot page translation reigster */
    set32(LCC_BSTRL, bootpg);
    set32(LCC_BSTAR, (LCC_BSTAR_EN |
                      LCC_BSTAR_LAWTRGT(LAW_TRGT_IFC) |
                      LAW_SIZE_4KB));
    (void)get32(LCC_BSTAR); /* read back to sync */

    /* Enable time base on current core only */
    set32(RCPM_PCTBENR, (1 << whoami));

    /* Release the CPU core(s) */
    set32(DCFG_BRR, all_cores);
    __asm__ __volatile__("sync; isync; msync");

    /* wait for other core to start */
    while (timeout) {
        for (i = 0; i < CPU_NUMCORES; i++) {
            uint32_t* entry = (uint32_t*)(spin_table_addr +
                (i * ENTRY_SIZE) + ENTRY_ADDR_LOWER);
            if (*entry) {
                active_cores |= (1 << i);
            }
        }
        if ((active_cores & all_cores) == all_cores) {
            break;
        }

        udelay(100);
        timeout--;
    }

    if (timeout == 0) {
        wolfBoot_printf("MP: Timeout enabling additional cores!\n");
    }

    /* Disable all timebases */
    set32(RCPM_PCTBENR, 0);

    /* Reset our timebase */
    mtspr(SPRN_TBWU, 0);
    mtspr(SPRN_TBWL, 0);

    /* Enable timebase for all cores */
    set32(RCPM_PCTBENR, all_cores);
}

static void hal_mp_init(void)
{
    uint32_t *fixup = (uint32_t*)&_mp_page_start;
    size_t bootpg;
    int i_tlb = 0; /* always 0 */
    size_t i;
    const uint32_t *s;
    uint32_t *d;

    /* Assign virtual boot page at end of DDR */
    bootpg = DDR_ADDRESS + DDR_SIZE - BOOT_ROM_SIZE;

    /* Store the boot page address for use by additional CPU cores */
    _bootpg_addr = bootpg;

    /* map reset page to bootpg so we can copy code there */
    disable_tlb1(i_tlb);
    set_tlb(1, i_tlb, BOOT_ROM_ADDR, bootpg, 0, /* tlb, epn, rpn, urpn */
        MAS3_SX | MAS3_SW | MAS3_SR, MAS2_I | MAS2_G, /* perms, wimge */
        0, BOOKE_PAGESZ_4K, 1); /* ts, esel, tsize, iprot */

    /* copy startup code to virtually mapped boot address */
    /* do not use memcpy due to compiler array bounds report (not valid) */
    s = (const uint32_t*)fixup;
    d = (uint32_t*)BOOT_ROM_ADDR;
    for (i = 0; i < BOOT_ROM_SIZE/4; i++) {
        d[i] = s[i];
    }

    /* start core and wait for it to be enabled */
    hal_mp_up(bootpg);
}
#endif /* ENABLE_MP */



void hal_init(void)
{
    law_init();

#ifdef DEBUG_UART
    uart_init();
    uart_write("wolfBoot HAL Init\n", 18);
#endif

    hal_flash_init();
    hal_cpld_init();

#ifdef ENABLE_QE
    if (hal_qe_init() != 0) {
        wolfBoot_printf("QE: Engine init failed!\n");
    }
#endif
#ifdef ENABLE_FMAN
    if (hal_fman_init() != 0) {
        wolfBoot_printf("FMAN: init failed!\n");
    }
#endif
#ifdef ENABLE_MP
    hal_mp_init();
#endif

    /* Hardware Tests */
#if defined(ENABLE_DDR) && defined(TEST_DDR)
    if (test_ddr() != 0) {
        wolfBoot_printf("DDR Test Failed!\n");
    }
#endif

#if defined(ENABLE_IFC) && defined(TEST_FLASH)
    if (test_flash() != 0) {
        wolfBoot_printf("Flash Test Failed!\n");
    }
#endif

#if defined(ENABLE_ESPI) && defined(TEST_TPM)
    if (test_tpm() != 0) {
        wolfBoot_printf("TPM Test Failed!\n");
    }
#endif
}

/* wait for toggle to stop and status mask to be met within microsecond timeout */
static int hal_flash_status_wait(uint32_t sector, uint16_t mask, uint32_t timeout_us)
{
    int ret = 0;
    uint32_t timeout = 0;
    uint16_t read1, read2;

    do {
        /* detection of completion happens when reading status bits DQ6 and DQ2 stop toggling (0x44) */
        /* Only the */
        read1 = FLASH_IO8_READ(sector, 0);
        if ((read1 & AMD_STATUS_TOGGLE) == 0)
            read1 = FLASH_IO8_READ(sector, 0);
        read2 = FLASH_IO8_READ(sector, 0);
        if ((read2 & AMD_STATUS_TOGGLE) == 0)
            read2 = FLASH_IO8_READ(sector, 0);
    #ifdef DEBUG_FLASH
        wolfBoot_printf("Wait toggle %x -> %x\n", read1, read2);
    #endif
        if (read1 == read2 && ((read1 & mask) == mask))
            break;
        udelay(1);
    } while (timeout++ < timeout_us);
    if (timeout >= timeout_us) {
        ret = -1; /* timeout */
    }
#ifdef DEBUG_FLASH
    wolfBoot_printf("Wait done (%d tries): %x -> %x\n",
        timeout, read1, read2);
#endif
    return ret;
}

int hal_flash_write(uint32_t address, const uint8_t *data, int len)
{
    uint32_t i, pos, sector, offset, xfer, nwords;

    /* adjust for flash base */
    if (address >= FLASH_BASE_ADDR)
        address -= FLASH_BASE_ADDR;

#ifdef DEBUG_FLASH
    wolfBoot_printf("Flash Write: Ptr %p -> Addr 0x%x (len %d)\n",
        data, address, len);
#endif

    pos = 0;
    while (len > 0) {
        /* dertermine sector address */
        sector = (address / FLASH_SECTOR_SIZE);
        offset = address - (sector * FLASH_SECTOR_SIZE);
        offset /= (FLASH_CFI_WIDTH/8);
        xfer = len;
        if (xfer > FLASH_PAGE_SIZE)
            xfer = FLASH_PAGE_SIZE;
        nwords = xfer / (FLASH_CFI_WIDTH/8);

    #ifdef DEBUG_FLASH
        wolfBoot_printf("Flash Write: Sector %d, Offset %d, Len %d, Pos %d\n",
            sector, offset, xfer, pos);
    #endif

        hal_flash_unlock_sector(sector);
        FLASH_IO8_WRITE(sector, offset, AMD_CMD_WRITE_TO_BUFFER);
    #if FLASH_CFI_WIDTH == 16
        FLASH_IO16_WRITE(sector, offset, (nwords-1));
    #else
        FLASH_IO8_WRITE(sector, offset, (nwords-1));
    #endif

        for (i=0; i<nwords; i++) {
            const uint8_t* ptr = &data[pos];
        #if FLASH_CFI_WIDTH == 16
            FLASH_IO16_WRITE(sector, i, *((const uint16_t*)ptr));
        #else
            FLASH_IO8_WRITE(sector, i, *ptr);
        #endif
            pos += (FLASH_CFI_WIDTH/8);
        }
        FLASH_IO8_WRITE(sector, offset, AMD_CMD_WRITE_BUFFER_CONFIRM);
        /* Typical 410us */

        /* poll for program completion - max 200ms */
        hal_flash_status_wait(sector, 0x44, 200*1000);

        address += xfer;
        len -= xfer;
    }
    return 0;
}

int hal_flash_erase(uint32_t address, int len)
{
    uint32_t sector;

    /* adjust for flash base */
    if (address >= FLASH_BASE_ADDR)
        address -= FLASH_BASE_ADDR;

    while (len > 0) {
        /* dertermine sector address */
        sector = (address / FLASH_SECTOR_SIZE);

    #ifdef DEBUG_FLASH
        wolfBoot_printf("Flash Erase: Sector %d, Addr 0x%x, Len %d\n",
            sector, address, len);
    #endif

        hal_flash_unlock_sector(sector);
        FLASH_IO8_WRITE(sector, FLASH_UNLOCK_ADDR1, AMD_CMD_ERASE_START);
        hal_flash_unlock_sector(sector);
        FLASH_IO8_WRITE(sector, 0, AMD_CMD_ERASE_SECTOR);
        /* block erase timeout = 50us - for additional sectors */
        /* Typical is 200ms (max 1100ms) */

        /* poll for erase completion - max 1.1 sec */
        hal_flash_status_wait(sector, 0x4C, 1100*1000);

        address += FLASH_SECTOR_SIZE;
        len -= FLASH_SECTOR_SIZE;
    }
    return 0;
}

static void hal_flash_unlock_sector(uint32_t sector)
{
    /* Unlock sequence */
    FLASH_IO8_WRITE(sector, FLASH_UNLOCK_ADDR1, AMD_CMD_UNLOCK_START);
    FLASH_IO8_WRITE(sector, FLASH_UNLOCK_ADDR2, AMD_CMD_UNLOCK_ACK);
}

void hal_flash_unlock(void)
{
    hal_flash_unlock_sector(0);
}

void hal_flash_lock(void)
{

}

void hal_prepare_boot(void)
{

}

#ifdef MMU
void* hal_get_dts_address(void)
{
    return (void*)WOLFBOOT_DTS_BOOT_ADDRESS;
}
#endif

#if defined(ENABLE_DDR) && defined(TEST_DDR)

#ifndef TEST_DDR_OFFSET
#define TEST_DDR_OFFSET     (2 * 1024 * 1024)
#endif
#ifndef TEST_DDR_TOTAL_SIZE
#define TEST_DDR_TOTAL_SIZE (2 * 1024)
#endif
#ifndef TEST_DDR_CHUNK_SIZE
#define TEST_DDR_CHUNK_SIZE 1024
#endif

static int test_ddr(void)
{
    int ret = 0;
    int i;
    uint32_t *ptr = (uint32_t*)(DDR_ADDRESS + TEST_DDR_OFFSET);
    uint32_t tmp[TEST_DDR_CHUNK_SIZE/4];
    uint32_t total = 0;

    while (total < TEST_DDR_TOTAL_SIZE) {
        /* test write to DDR */
        for (i=0; i<TEST_DDR_CHUNK_SIZE/4; i++) {
            ptr[i] = (uint32_t)i;
        }

        /* test read from DDR */
        for (i=0; i<TEST_DDR_CHUNK_SIZE/4; i++) {
            tmp[i] = ptr[i];
        }

        /* compare results */
        for (i=0; i<TEST_DDR_CHUNK_SIZE/4; i++) {
            if (tmp[i] != (uint32_t)i) {
                ret = -1;
                break;
            }
        }
        total += TEST_DDR_CHUNK_SIZE;
        ptr += TEST_DDR_CHUNK_SIZE;
    }

    return ret;
}
#endif /* ENABLE_DDR && TEST_DDR */

#if defined(ENABLE_IFC) && defined(TEST_FLASH)

#ifndef TEST_ADDRESS
    /* 0xEC100000 (1MB offset) */
    #define TEST_ADDRESS (FLASH_BASE_ADDR + (1 * 0x100000))
#endif

/* #define TEST_FLASH_READONLY */

static uint32_t pageData[FLASH_PAGE_SIZE/sizeof(uint32_t)]; /* force 32-bit alignment */

static int test_flash(void)
{
    int ret;
    uint32_t i;
    uint8_t* pagePtr = (uint8_t*)TEST_ADDRESS;

#ifndef TEST_FLASH_READONLY
    /* Erase sector */
    ret = hal_flash_erase(TEST_ADDRESS, sizeof(pageData));
    wolfBoot_printf("Erase Sector: Ret %d\n", ret);

    /* Write Pages */
    for (i=0; i<sizeof(pageData); i++) {
        ((uint8_t*)pageData)[i] = (i & 0xff);
    }
    ret = hal_flash_write(TEST_ADDRESS, (uint8_t*)pageData, sizeof(pageData));
    wolfBoot_printf("Write Page: Ret %d\n", ret);
#endif /* !TEST_FLASH_READONLY */

    /* invalidate cache */
    flush_cache((uint32_t)pagePtr, sizeof(pageData));

    wolfBoot_printf("Checking...\n");
    ret = memcmp(pageData, pagePtr, sizeof(pageData));
    if (ret != 0) {
        wolfBoot_printf("Check Data @ %d failed\n", ret);
        return -ret;
    }

    wolfBoot_printf("Flash Test Passed\n");
    return ret;
}
#endif /* ENABLE_IFC && TEST_FLASH */

#if defined(ENABLE_ESPI) && defined(TEST_TPM)
int test_tpm(void)
{
    /* Read 4 bytes at TIS address D40F00. Assumes 0 wait state on TPM */
    uint8_t tx[8] = {0x83, 0xD4, 0x0F, 0x00,
                     0x00, 0x00, 0x00, 0x00};
    uint8_t rx[8] = {0};

    hal_espi_init(SPI_CS_TPM, 2000000, 0);
    hal_espi_xfer(SPI_CS_TPM, tx, rx, (uint32_t)sizeof(rx), 0);

    wolfBoot_printf("RX: 0x%x\n", *((uint32_t*)&rx[4]));
    return rx[4] != 0xFF ? 0 : -1;
}
#endif
