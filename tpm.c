/* tpm.c
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
 * along with EnactTrust. If not, see <https://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <string.h>
/* wolfTPM TPM 2.0 library - GPLv2 */
#include <wolftpm/options.h>
/* wolfCrypt Cryptographic library - GPLv2 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
/* EnactTrust */
#include "enact.h"

static int verbose = 0;

#define FILE_CHUNK_SIZE 1024 /* Size of the chunk used to process files */
#define DER_SIZE 256 /* Size of DER formatted output */

int tpm_init(ENACT_TPM *tpm)
{
    int ret = ENACT_ERROR;

    if(tpm == NULL) {
        return BAD_ARG;
    }

    if(wolfTPM2_Init(&tpm->dev, NULL, NULL) != TPM_RC_SUCCESS) {
        printf("Unable to access the TPM. Check your permissions.\n");
    }

    if(wolfTPM2_CreateEK(&tpm->dev, &tpm->ek, TPM_ALG_RSA) != TPM_RC_SUCCESS) {
        printf("Unable to create Endorsement Key(EK)\n");
        printf("EK is required for onboarding\n");
    }

    if(wolfTPM2_StartSession(&tpm->dev, &tpm->sessionA,
                             &tpm->ek, NULL, TPM_SE_HMAC,
                             TPM_ALG_CFB) != TPM_RC_SUCCESS) {
        if(verbose) printf("Failed to create HMAC session\n");
    }
    else {
        ret = ENACT_SUCCESS;
    }

    return ret;
}


int tpm_deinit(ENACT_TPM *tpm)
{
    int ret = 0;

    if(tpm == NULL) {
        return BAD_ARG;
    }

#if 0
    wolfTPM2_NVDeleteKey(&tpm->dev, TPM_RH_OWNER, &tpm->primary);
    wolfTPM2_NVDeleteKey(&tpm->dev, TPM_RH_OWNER, &tpm->ak);
#endif

    ret = wolfTPM2_UnloadHandle(&tpm->dev, &tpm->primary.handle);
    ret |= wolfTPM2_UnloadHandle(&tpm->dev, &tpm->ak.handle);
    ret |= wolfTPM2_UnloadHandle(&tpm->dev, &tpm->ek.handle);
    ret |= wolfTPM2_UnloadHandle(&tpm->dev, &tpm->sessionA.handle);
    ret |= wolfTPM2_Cleanup(&tpm->dev);
    if(ret == TPM_RC_SUCCESS) {
        ret = ENACT_SUCCESS;
        if(verbose) printf("TPM device released\n");
    }
    else {
        ret = ENACT_ERROR;
        if(verbose) printf("Failure while releasing the TPM device\n");
    }

    return ret;
}


int tpm_createEK(ENACT_TPM *tpm)
{
    int ret = 0;

    ret = wolfTPM2_CreateEK(&tpm->dev, &tpm->ek, TPM_ALG_ECC);
    return ret == TPM_RC_SUCCESS ? ENACT_SUCCESS : ENACT_ERROR;
}


int tpm_createSRK(ENACT_TPM *tpm)
{
    int ret = 0;

    /* Check if SRK already exists */
    ret = wolfTPM2_ReadPublicKey(&tpm->dev, &tpm->primary, ENACT_TPM_HANDLE_SRK);
    if(ret != 0) {
        printf("Primary TPM key does not exist, creating a new Primary Key\n");
        ret = wolfTPM2_CreateSRK(&tpm->dev, &tpm->primary, TPM_ALG_ECC, NULL, 0);
        if(ret == TPM_RC_SUCCESS) {
            ret = wolfTPM2_NVStoreKey(&tpm->dev, TPM_RH_OWNER, &tpm->primary,
                                      ENACT_TPM_HANDLE_SRK);
        }
    }
    else {
        printf("SRK is persistent\n");
    }

    return ret == TPM_RC_SUCCESS ? ENACT_SUCCESS : ENACT_ERROR;
}


int tpm_createAK(ENACT_TPM *tpm)
{
    int ret = 0;

    /* Check if AK already exists */
    ret = wolfTPM2_ReadPublicKey(&tpm->dev, &tpm->ak, ENACT_TPM_HANDLE_AK);
    if(ret != 0) {
        printf("Attestation TPM key does not exist, creating a new AK\n");
        /* If not, create a new attestation key and persist it */
        ret = wolfTPM2_CreateAndLoadAIK(&tpm->dev, &tpm->ak, TPM_ALG_ECC,
                                        &tpm->primary, NULL, 0);
        if(ret == TPM_RC_SUCCESS) {
            ret = wolfTPM2_NVStoreKey(&tpm->dev, TPM_RH_OWNER, &tpm->ak,
                                      ENACT_TPM_HANDLE_AK);
        }
    }
    else {
        printf("AK is persistent\n");
    }


#ifdef DEBUG_VERBOSE
    if(ret == TPM_RC_SUCCESS) {
        printf("AK Name Digest\n");
        TPM2_PrintBin(tpm->ak.handle.name.name, tpm->ak.handle.name.size);
    }
#endif

    return ret == TPM_RC_SUCCESS ? ENACT_SUCCESS : ENACT_ERROR;
}


int tpm_pcrReset(UINT32 pcrIndex)
{
    int ret = ENACT_ERROR;
    PCR_Reset_In cmd_pcrReset;

    cmd_pcrReset.pcrHandle = pcrIndex;
    ret = TPM2_PCR_Reset(&cmd_pcrReset);
    if(ret == TPM_RC_SUCCESS) {
        if(verbose) printf("PCR%d successfully reset\n", pcrIndex);
        ret = ENACT_SUCCESS;
    }
    else {
        if(verbose) printf("Failed to reset PCR%d\n", pcrIndex);
    }

    return ret;
}


int tpm_pcrRead(ENACT_EVIDENCE *attested, UINT32 pcrIndex)
{
    int ret = ENACT_ERROR;
    PCR_Read_In cmd_pcrRead;
    PCR_Read_Out resp_pcrRead;

    if(attested == NULL) {
        return BAD_ARG;
    }

    TPM2_SetupPCRSel(&cmd_pcrRead.pcrSelectionIn, TPM_ALG_SHA256, pcrIndex);
    ret = TPM2_PCR_Read(&cmd_pcrRead, &resp_pcrRead);
    if(ret == TPM_RC_SUCCESS) {
        ret = ENACT_SUCCESS;
#ifdef DEBUG_VERBOSE
        if(verbose) {
            printf("PCR%d value:\n", pcrIndex);
            TPM2_PrintBin(resp_pcrRead.pcrValues.digests[0].buffer,
                          resp_pcrRead.pcrValues.digests[0].size);
        }
#endif /* DEBUG_VERBOSE */
    }

    return ret;
}


int tpm_pcrExtend(ENACT_FILES *files, UINT32 pcrIndex)
{
    int i, len, ret = ENACT_ERROR;
    PCR_Extend_In cmd_pcrExtend;
    BYTE hash[TPM_SHA256_DIGEST_SIZE];
    BYTE dataBuffer[FILE_CHUNK_SIZE];
    FILE *fp;
    wc_Sha256 sha256;

    cmd_pcrExtend.pcrHandle = pcrIndex;
    cmd_pcrExtend.digests.count = 1;
    cmd_pcrExtend.digests.digests[0].hashAlg = TPM_ALG_SHA256;

    for(i=0; i < files->count; i++) {
        fp = XFOPEN(files->name[i], "rb");
        if(fp) {
            wc_InitSha256(&sha256);
            while(!XFEOF(fp)) {
                len = XFREAD(dataBuffer, 1, sizeof(dataBuffer), fp);
                if(len) {
                    wc_Sha256Update(&sha256, dataBuffer, (int)len);
                }
            }
            fclose(fp);
            wc_Sha256Final(&sha256, hash);
#ifdef DEBUG_VERBOSE
            if(verbose) {
                printf("Hash of %s file:\n", files->name[i]);
                TPM2_PrintBin(hash, TPM_SHA256_DIGEST_SIZE);
            }
#endif /* DEBUG_VERBOSE */
        }

        XMEMCPY(cmd_pcrExtend.digests.digests[0].digest.H, hash,
                TPM_SHA256_DIGEST_SIZE);

        ret = TPM2_PCR_Extend(&cmd_pcrExtend);
        if(ret == TPM_RC_SUCCESS) {
            if(verbose) printf("File %s extended into PCR%d\n", files->name[i],
                   cmd_pcrExtend.pcrHandle);
            ret = ENACT_SUCCESS;
        }
        else {
            if(verbose) printf("PCR Extend failed\n");
            //tpm_printError(ret);
        }
    }

    return ret;
}

int tpm_createQuote(ENACT_TPM *tpm, ENACT_EVIDENCE *attested)
{
    int ret = ENACT_ERROR;
    Quote_In quoteCmd;
    Quote_Out quoteResp;

    if(tpm == NULL || attested == NULL) {
        return BAD_ARG;
    }

    quoteCmd.signHandle = tpm->ak.handle.hndl;
    quoteCmd.inScheme.scheme = TPM_ALG_ECDSA;
    quoteCmd.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
    quoteCmd.qualifyingData.size = sizeof(attested->nodeid);
    XMEMCPY((byte*)&quoteCmd.qualifyingData.buffer,
            (byte*)&attested->nodeid,
            quoteCmd.qualifyingData.size);

    wolfTPM2_SetAuthHandle(&tpm->dev, 0, &tpm->ak.handle);
    TPM2_SetupPCRSel(&quoteCmd.PCRselect, TPM_ALG_SHA256, ENACT_TPM_QUOTE_PCR);
    ret = TPM2_Quote(&quoteCmd, &quoteResp);
    if(ret == TPM_RC_SUCCESS) {
        ret = TPM2_ParseAttest(&quoteResp.quoted, &attested->data);
        if(ret == TPM_RC_SUCCESS) {
            if(attested->data.magic == TPM_GENERATED_VALUE) {
                if(verbose) printf("Evidence created.\n");
                XMEMCPY((byte*)&attested->data,
                        (byte*)&quoteResp.quoted.attestationData,
                        quoteResp.quoted.size);
                XMEMCPY((byte*)&attested->signature,
                        (byte*)&quoteResp.signature,
                        sizeof(quoteResp.signature));
                XMEMCPY((byte*)&attested->raw,
                        (byte*)&quoteResp.quoted,
                        sizeof(quoteResp.quoted));
                ret = ENACT_SUCCESS;
            }
            else {
                if(verbose) printf("Invalid TPM magic value.\n");
            }
        }
        else {
            if(verbose) printf("Failure to process the new evidence.\n");
        }
    }
    else {
        if(verbose) printf("Failure to create evidence.\n");
    }

    return ret;
}

int tpm_exportEccPubToPem(ENACT_TPM *tpm, ENACT_PEM *pem, const char *filename)
{
    int ret = 0;
    int derSize = 0;
    byte derKey[DER_SIZE];
    ecc_key eccKey;

    ret = wc_ecc_init(&eccKey);
    if(ret) {
        if(verbose) printf("Failure to prepare for the export operation.\n");
        return ret;
    }

    if(!strcmp(filename, ENACT_EKPEM_FILENAME)) {
        ret = wolfTPM2_EccKey_TpmToWolf(&tpm->dev, &tpm->ek, &eccKey);
    }
    else if(!strcmp(filename, ENACT_AKPEM_FILENAME)) {
        ret = wolfTPM2_EccKey_TpmToWolf(&tpm->dev, &tpm->ak, &eccKey);
    }
    else {
        ret = ENACT_ERROR;
    }
    if(ret) {
        if(verbose) printf("Failure to prepare the TPM ECC key for export.\n");
        return ret;
    }

    ret = wc_EccPublicKeyToDer(&eccKey, derKey, sizeof(derKey), 1);
    if(ret > 0) {
        derSize = ret;
    }
    else {
        if(verbose) printf("Failure when converting the TPM ECC key.\n");
        return ret;
    }

    ret = wc_DerToPem(derKey, derSize, pem->key, sizeof(pem->key), ECC_PUBLICKEY_TYPE);
    if(ret > 0) {
        pem->size = ret;
        ret = ENACT_SUCCESS;
        if(verbose) {
            printf("Converted TPM pub key to PEM (size=%d)\n", pem->size);
#ifdef DEBUG_VERBOSE
            TPM2_PrintBin(pem->key, pem->size);
#endif
        }
    }
    else {
        if(verbose) printf("Failure to convert the ECC key to PEM format.\n");
        return ret;
    }

    return ret;
}

void tpm_printError(int verbose, int ret)
{
    if(verbose) printf("TPM error 0x%x: %s\n", ret, TPM2_GetRCString(ret));
}
