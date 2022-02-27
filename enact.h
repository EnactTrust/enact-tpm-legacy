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
 * along with Foobar.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _ENACT_H_
#define _ENACT_H_

#include <wolftpm/tpm2_wrap.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Return codes */
#define ENACT_SUCCESS        0
#define ENACT_ERROR         -1
#define ENACT_ERROR_START   -2
#define ENACT_FAILURE       -127
#define BAD_ARG             -128

#define UUID_V4_SIZE 36
#define ENACT_TPM_QUOTE_PCR     23
#define ENACT_TPM_HANDLE_SRK    0x81010010
#define ENACT_TPM_HANDLE_AK     0x81010011

#define ENACT_QUOTE_FILENAME "evidence.blob\0"
#define ENACT_AKRAW_FILENAME "ak.pub\0"
#define ENACT_AKPEM_FILENAME "ak.pem\0"
#define ENACT_EKRAW_FILENAME "ek.pub\0"
#define ENACT_EKPEM_FILENAME "ek.pem\0"
#define ENACT_SIGNATURE_FILENAME "signature.blob\0"
#define ENACT_NODEID_TEMPFILE "node.id"

/* EnactTrust defines for CI & testing */
#define URL_WEBTEST     "http://ptsv2.com/t/t48o8-1645500358/post"
#define URL_LOCALHOST   "http://localhost:8000/"
#define URL_LOCALHOST_NODE_PEM      "http://localhost:8000/node/pem"
#define URL_LOCALHOST_NODE_GOLDEN   "http://localhost:8000/node/golden"
#define URL_LOCALHOST_NODE_EVIDENCE "http://localhost:8000/node/evidence"

/* EnactTrust & Veraison API as decsribed in the api-integration UML diagram */
#define ENACT_BACKEND       "http://a3s.enacttrust.com/"
#define ENACT_API_PEM       "node/pem"
#define ENACT_API_SECRET    "node/secret"
#define ENACT_API_GOLDEN    "node/golden"
#define ENACT_API_EVIDENCE  "node/evidence"

#define ENACT_API_PEM_ARG_AK    "ak_pub"
#define ENACT_API_PEM_ARG_EK    "ek_pub"
#define ENACT_API_PEM_ARG_AKNAME "ak_name"

#define ENACT_API_GOLDEN_ARG_GOLDEN "golden_blob"
#define ENACT_API_GOLDEN_ARG_SIGN   "signature_blob"
#define ENACT_API_GOLDEN_ARG_NODEID "node_id"

#define ENACT_API_EVIDENCE_ARG_EVIDENCE "evidence_blob"
#define ENACT_API_EVIDENCE_ARG_SIGN     ENACT_API_GOLDEN_ARG_SIGN
#define ENACT_API_EVIDENCE_ARG_NODEID   ENACT_API_GOLDEN_ARG_NODEID

#define MAX_FILE_COUNT 20
#define MAX_FILE_NAME 100
#define MAX_PEM_SIZE 512
#define MAX_CMD_SIZE 200

typedef struct ENACT_TPM {
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY ek;
    WOLFTPM2_KEY primary; /* Storage Key */
    WOLFTPM2_KEY ak; /* Attestation Key */
    WOLFTPM2_SESSION sessionA; /* Param Enc */
} ENACT_TPM;

typedef struct ENACT_EVIDENCE {
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
