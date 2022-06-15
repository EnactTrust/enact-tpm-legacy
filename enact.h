/* enact.h
 *
 * Copyright (C) 2018-2021 DesignFirst OU
 * Copyright (C) 2022 EnactTrust LTD
 *
 * This file is part of EnactTrust.
 *
 * EnactTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * EnactTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EnactTrust.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _ENACT_H_
#define _ENACT_H_

#include "enact_api.h"
#include <wolftpm/tpm2_wrap.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define ENACT_VERSION_STRING "0.6.5"
#define ENACT_VERSION_HEX 0x00006050

/* Return codes */
#define ENACT_SUCCESS        0
#define ENACT_ERROR         -1
#define ENACT_ERROR_START   -2
#define NOT_IMPLEMENTED     -127
#define BAD_ARG             -128

#define UUID_V4_SIZE    36
#define UUID_V4_CHARS   32
#define UUID_V4_BYTES   16

#define ENACT_TPM_QUOTE_PCR     23
#define ENACT_TPM_HANDLE_SRK    0x81010010
#define ENACT_TPM_HANDLE_AK     0x81010011
#define ENACT_TPM_HANDLE_NVRAM  0x0180020A

#define ENACT_QUOTE_FILENAME "evidence.blob\0"
#define ENACT_QUOTE_SIGNATURE_FILENAME "signature.blob\0"
#define ENACT_GPIO_FILENAME "gpio.blob\0"
#define ENACT_GPIO_SIGNATURE_FILENAME "gpiosign.blob\0"
#define ENACT_AKRAW_FILENAME "ak.pub\0"
#define ENACT_AKPEM_FILENAME "ak.pem\0"
#define ENACT_EKRAW_FILENAME "ek.pub\0"
#define ENACT_EKPEM_FILENAME "ek.pem\0"
#define ENACT_EKCERT_FILENAME "ek.cert\0"
#define ENACT_NODEID_TEMPFILE "node.id\0"
#define ENACT_DEMO_PATH "/demo/\0"    /* Quick start protects this folder */
#define ENACT_DEMO_FILE "/etc/passwd\0" /* Protect the Linux password file */

#define MAX_FILE_COUNT 20
#define MAX_FILE_NAME 100
#define MAX_PEM_SIZE 512
#define MAX_CMD_SIZE 200

#ifdef ENACT_TPM_GPIO_ENABLE
typedef struct ENACT_TPM_GPIO {
    WOLFTPM2_NV nv;
    WOLFTPM2_HANDLE nvParent;
    TPMI_GPIO_MODE gpioMode;
    TPM_HANDLE nvIndex;
} ENACT_TPM_GPIO;
#endif /* ENACT_TPM_GPIO_ENABLE */

typedef struct ENACT_TPM {
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY ek;
    WOLFTPM2_KEY primary; /* Storage Key */
    WOLFTPM2_KEY ak; /* Attestation Key */
    WOLFTPM2_SESSION sessionA; /* Param Enc */
#ifdef ENACT_TPM_GPIO_ENABLE
    ENACT_TPM_GPIO gpio;
#endif
} ENACT_TPM;

typedef struct ENACT_EVIDENCE {
    char nodeid[UUID_V4_BYTES];
    TPM2B_ATTEST raw;
    TPMS_ATTEST data;
    TPMT_SIGNATURE signature;
} ENACT_EVIDENCE;

typedef struct ENACT_FILES {
    char name[MAX_FILE_COUNT][MAX_FILE_NAME];
    int count;
} ENACT_FILES;

typedef struct ENACT_PEM {
    byte key[MAX_PEM_SIZE];
    int size;
} ENACT_PEM;

#ifdef __cplusplus
    }
#endif

#endif /* _ENACT_H_ */
