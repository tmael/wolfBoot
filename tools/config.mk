#Defaults, used by CI
ifeq ($(ARCH),)
  ARCH?=ARM
  TARGET?=stm32f4
  SIGN?=ED25519
  HASH?=SHA256
  MCUXPRESSO?=$(HOME)/src/FRDM-K64F
  MCUXPRESSO_CPU=MK64FN1M0VLL12
  MCUXPRESSO_DRIVERS?=$(MCUXPRESSO)/devices/MK64F12
  MCUXPRESSO_CMSIS?=$(MCUXPRESSO)/CMSIS
  FREEDOM_E_SDK?=$(HOME)/src/freedom-e-sdk
  STM32CUBE?=$(HOME)/STM32Cube/Repository/STM32Cube_FW_WB_V1.3.0
  CYPRESS_PDL?=$(HOME)/src/psoc6pdl
  CYPRESS_TARGET_LIB?=$(HOME)/src/TARGET_CY8CKIT-062S2-43012
  CYPRESS_CORE_LIB?=$(HOME)/src/cypress-core-lib
  DEBUG?=0
  VTOR?=1
  CORTEX_M0?=0
  NO_ASM?=0
  EXT_FLASH?=0
  SPI_FLASH?=0
  NO_XIP?=0
  UART_FLASH?=0
  ALLOW_DOWNGRADE?=0
  NVM_FLASH_WRITEONCE?=0
  WOLFBOOT_VERSION?=0
  V?=0
  NO_MPU?=0
  SPMATH?=1
  RAM_CODE?=0
  DUALBANK_SWAP?=0
  IMAGE_HEADER_SIZE?=256
  PKA?=1
  WOLFTPM?=0
  WOLFBOOT_PARTITION_SIZE?=0x20000
  WOLFBOOT_SECTOR_SIZE?=0x20000
  WOLFBOOT_PARTITION_BOOT_ADDRESS?=0x20000
  WOLFBOOT_PARTITION_UPDATE_ADDRESS?=0x40000
  WOLFBOOT_PARTITION_SWAP_ADDRESS?=0x60000
  WOLFBOOT_DTS_BOOT_ADDRESS?=0x30000
  WOLFBOOT_DTS_UPDATE_ADDRESS=0x50000
  WOLFBOOT_LOAD_ADDRESS?=0x200000
  WOLFBOOT_LOAD_DTS_ADDRESS?=0x400000
endif


CONFIG_VARS:= ARCH TARGET SIGN HASH MCUXPRESSO MCUXPRESSO_CPU MCUXPRESSO_DRIVERS \
	MCUXPRESSO_CMSIS FREEDOM_E_SDK STM32CUBE CYPRESS_PDL CYPRESS_CORE_LIB CYPRESS_TARGET_LIB DEBUG VTOR \
	CORTEX_M0 NO_ASM EXT_FLASH SPI_FLASH NO_XIP UART_FLASH ALLOW_DOWNGRADE NVM_FLASH_WRITEONCE \
	WOLFBOOT_VERSION V NO_MPU \
	SPMATH RAM_CODE DUALBANK_SWAP IMAGE_HEADER_SIZE PKA WOLFTPM \
	WOLFBOOT_PARTITION_SIZE WOLFBOOT_SECTOR_SIZE  \
	WOLFBOOT_PARTITION_BOOT_ADDRESS WOLFBOOT_PARTITION_UPDATE_ADDRESS \
	WOLFBOOT_PARTITION_SWAP_ADDRESS WOLFBOOT_LOAD_ADDRESS \
	WOLFBOOT_LOAD_DTS_ADDRESS
