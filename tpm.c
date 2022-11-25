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
#include "tpm.h"

static int verbose = 0;

#define FILE_CHUNK_SIZE 1024 /* Size of the chunk used to process files */
#define DER_SIZE 256 /* Size of DER formatted output */


void tpm_printError(int verbose, int ret)
{
    if(verbose) printf("TPM error 0x%x: %s\n", ret, TPM2_GetRCString(ret));
}

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
        if(verbose) printf("Primary TPM key is persistent\n");
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
        if(verbose) printf("Attestation TPM key is persistent\n");
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


int tpm_pcrRead(ENACT_EVIDENCE *evidence, UINT32 pcrIndex)
{
    int ret = ENACT_ERROR;
    PCR_Read_In cmd_pcrRead;
    PCR_Read_Out resp_pcrRead;

    if(evidence == NULL) {
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
            tpm_printError(verbose, ret);
        }
    }

    return ret;
}

int tpm_createQuote(ENACT_TPM *tpm, ENACT_EVIDENCE *evidence)
{
    int ret = ENACT_ERROR;
    Quote_In quoteCmd;
    Quote_Out quoteResp;

    if(tpm == NULL || evidence == NULL) {
        return BAD_ARG;
    }

    quoteCmd.signHandle = tpm->ak.handle.hndl;
    quoteCmd.inScheme.scheme = TPM_ALG_ECDSA;
    quoteCmd.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
    quoteCmd.qualifyingData.size = sizeof(evidence->nodeid) + ENACT_NONCE_SIZE;
    /* Prepare nonce */
    XMEMCPY((byte*)&quoteCmd.qualifyingData.buffer,
            (byte*)&evidence->nonce,
            ENACT_NONCE_SIZE);
    /* Prepare nodeid */
    XMEMCPY((byte*)&quoteCmd.qualifyingData.buffer[ENACT_NONCE_SIZE],
            (byte*)&evidence->nodeid,
            sizeof(evidence->nodeid);

    wolfTPM2_SetAuthPassword(&tpm->dev, 0, NULL);
    wolfTPM2_UnsetAuth(&tpm->dev, 1);
    wolfTPM2_UnsetAuth(&tpm->dev, 2);

    TPM2_SetupPCRSel(&quoteCmd.PCRselect, TPM_ALG_SHA256, ENACT_TPM_QUOTE_PCR);
    ret = TPM2_Quote(&quoteCmd, &quoteResp);
    if(ret == TPM_RC_SUCCESS) {
        ret = TPM2_ParseAttest(&quoteResp.quoted, &evidence->data);
        if(ret == TPM_RC_SUCCESS) {
            if(evidence->data.magic == TPM_GENERATED_VALUE) {
                if(verbose) printf("Evidence created.\n");
                XMEMCPY((byte*)&evidence->data,
                        (byte*)&quoteResp.quoted.attestationData,
                        quoteResp.quoted.size);
                XMEMCPY((byte*)&evidence->signature,
                        (byte*)&quoteResp.signature,
                        sizeof(quoteResp.signature));
                XMEMCPY((byte*)&evidence->raw,
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

#ifdef ENACT_TPM_GPIO_ENABLE
int tpm_gpio_config(ENACT_TPM *tpm, int gpioPin)
{
    int ret = ENACT_ERROR;
    GpioConfig_In gpio;
    SetCommandSet_In setCmdSet;
    word32 nvAttributes;
    BYTE dummy = 0;

    XMEMSET(&setCmdSet, 0, sizeof(setCmdSet));
    XMEMSET(&tpm->gpio.nv, 0, sizeof(tpm->gpio.nv));
    XMEMSET(&tpm->gpio.nvParent, 0, sizeof(tpm->gpio.nvParent));

    wolfTPM2_UnsetAuth(&tpm->dev, 0);
    wolfTPM2_UnsetAuth(&tpm->dev, 1);
    wolfTPM2_UnsetAuth(&tpm->dev, 2);

    tpm->gpio.gpioMode = TPM_GPIO_MODE_PULLDOWN;
    tpm->gpio.nvIndex = TPM_NV_GPIO_SPACE + (gpioPin-TPM_GPIO_NUM_MIN);

    ret = wolfTPM2_NVDelete(&tpm->dev, TPM_RH_OWNER, tpm->gpio.nvIndex);
    if(ret == TPM_RC_SUCCESS || ret == (TPM_RC_HANDLE | TPM_RC_2)) {
        if(verbose) printf("GPIO NV index is available\n");
    }
    else {
        printf("Unable to access GPIO NV index\n");
        tpm_printError(verbose, ret);
        return ret;
    }

    setCmdSet.authHandle = TPM_RH_PLATFORM;
    setCmdSet.commandCode = TPM_CC_GPIO_Config;
    setCmdSet.enableFlag = 1;
    ret = TPM2_SetCommandSet(&setCmdSet);
    if(ret != TPM_RC_SUCCESS) {
        printf("GPIO config command missing\n");
        tpm_printError(verbose, ret);
        return ret;
    }

    /* GPIO is accessed using an NV Index that is under the PLATFORM auth */
    XMEMSET(&gpio, 0, sizeof(gpio));
    gpio.authHandle = TPM_RH_PLATFORM;
    gpio.config.count = 1;
    gpio.config.gpio[0].name = gpioPin;
    gpio.config.gpio[0].mode = tpm->gpio.gpioMode;
    gpio.config.gpio[0].index = tpm->gpio.nvIndex;
    if(verbose) printf("Configuring GPIO%d...\n", gpio.config.gpio[0].name);
    ret = TPM2_GPIO_Config(&gpio);
    if(ret != TPM_RC_SUCCESS) {
        printf("Configuration failed\n");
        tpm_printError(verbose, ret);
        return ret;
    }
    printf("TPM GPIO%d configured.\n", gpio.config.gpio[0].name);

    /* Configure NV Index for access to this GPIO */
    tpm->gpio.nvParent.hndl = TPM_RH_OWNER;
    ret = wolfTPM2_GetNvAttributesTemplate(tpm->gpio.nvParent.hndl, &nvAttributes);
    if(ret != TPM_RC_SUCCESS) {
        printf("NV attributes failed\n");
        return ret;
    }
    /* Define NV Index for GPIO */
    ret = wolfTPM2_NVCreateAuth(&tpm->dev, &tpm->gpio.nvParent,
                                &tpm->gpio.nv, tpm->gpio.nvIndex,
                                nvAttributes, sizeof(BYTE), NULL, 0);
    if(ret != 0 && ret != TPM_RC_NV_DEFINED) {
        printf("Creating GPIO NV index failed\n");
        tpm_printError(verbose, ret);
        return ret;
    }
    if(verbose) printf("GPIO NV index created\n");

    /* Writing a dummy byte has no impact on the input, but it is required */
    ret = wolfTPM2_NVWriteAuth(&tpm->dev, &tpm->gpio.nv, tpm->gpio.nvIndex,
                               &dummy, sizeof(dummy), 0);
    if(ret != TPM_RC_SUCCESS) {
            printf("Error at last GPIO configuration step.\n");
    }
    else {
        if(verbose) printf("GPIO is ready\n");
        ret = ENACT_SUCCESS;
    }

    return ret;
}

int tpm_gpio_read(ENACT_TPM *tpm, int gpio)
{
    int ret = ENACT_ERROR;
    BYTE gpioState = 0;
    word32 readSize = 0;

    XMEMSET(&tpm->gpio.nv, 0, sizeof(tpm->gpio.nv));
    XMEMSET(&tpm->gpio.nvParent, 0, sizeof(tpm->gpio.nvParent));

    wolfTPM2_UnsetAuth(&tpm->dev, 0);
    wolfTPM2_UnsetAuth(&tpm->dev, 1);
    wolfTPM2_UnsetAuth(&tpm->dev, 2);

    tpm->gpio.nvIndex = TPM_NV_GPIO_SPACE + (gpio-TPM_GPIO_NUM_MIN);

    /* Prep NV Index and its auth */
    tpm->gpio.nv.handle.hndl = tpm->gpio.nvIndex;
    tpm->gpio.nv.handle.auth.size = 0;
    tpm->gpio.nvParent.hndl = TPM_RH_OWNER;
    /* Read GPIO state */
    readSize = sizeof(gpioState);
    ret = wolfTPM2_NVReadAuth(&tpm->dev, &tpm->gpio.nv, tpm->gpio.nvIndex, &gpioState, &readSize, 0);
    if(ret == TPM_RC_SUCCESS) {
        ret = ENACT_SUCCESS;
        if(gpioState == 0x01) {
            printf("TPM GPIO%d is High.\n", gpio);
        }
        else if(gpioState == 0x00) {
            printf("TPM GPIO%d is Low.\n", gpio);
        }
        else {
            printf("GPIO%d level read, invalid value = 0x%X\n", gpio, gpioState);
        }
    }
    else {
        printf("Error while reading GPIO state\n");
    }

    return ret;
}

int tpm_gpio_certify(ENACT_TPM *tpm, ENACT_EVIDENCE *evidence, int gpio)
{
    int ret = ENACT_ERROR;
    NV_Certify_In nvCmd;
    NV_Certify_Out nvResp;

    XMEMSET(&nvCmd, 0, sizeof(nvCmd));
    XMEMSET(&nvResp, 0, sizeof(nvResp));

    tpm->gpio.nvIndex = TPM_NV_GPIO_SPACE + (gpio-TPM_GPIO_NUM_MIN);
    tpm->gpio.nvParent.hndl = TPM_RH_OWNER;

    nvCmd.signHandle = tpm->ak.handle.hndl;
    nvCmd.authHandle = tpm->gpio.nvParent.hndl;
    nvCmd.nvIndex = tpm->gpio.nvIndex;
    nvCmd.qualifyingData.size = sizeof(evidence->nodeid) + ENACT_NONCE_SIZE;
    /* Prepare nonce */
    XMEMCPY((byte*)&nvCmd.qualifyingData.buffer,
            (byte*)&evidence->nonce,
            ENACT_NONCE_SIZE);
    /* Prepare nodeid */
    XMEMCPY((byte*)&quoteCmd.qualifyingData.buffer[ENACT_NONCE_SIZE],
            (byte*)&evidence->nodeid,
            sizeof(evidence->nodeid);
    nvCmd.inScheme.scheme = TPM_ALG_ECDSA;
    nvCmd.inScheme.details.any.hashAlg = TPM_ALG_SHA256;
    nvCmd.offset = 0;
    nvCmd.size = 1; /* GPIO status is provided as a single byte */

    wolfTPM2_SetAuthPassword(&tpm->dev, 0, NULL);
    wolfTPM2_SetAuthPassword(&tpm->dev, 1, NULL);
    wolfTPM2_UnsetAuth(&tpm->dev, 2);

    ret = TPM2_NV_Certify(&nvCmd, &nvResp);
    if(ret == TPM_RC_SUCCESS) {
        ret = TPM2_ParseAttest(&nvResp.certifyInfo, &evidence->data);
        if(ret == TPM_RC_SUCCESS) {
            if(evidence->data.magic == TPM_GENERATED_VALUE) {
                if(verbose) printf("GPIO Evidence created.\n");
                XMEMCPY((byte*)&evidence->data,
                        (byte*)&nvResp.certifyInfo.attestationData,
                        nvResp.certifyInfo.size);
                XMEMCPY((byte*)&evidence->signature,
                        (byte*)&nvResp.signature,
                        sizeof(nvResp.signature));
                XMEMCPY((byte*)&evidence->raw,
                        (byte*)&nvResp.certifyInfo,
                        sizeof(nvResp.certifyInfo));
                ret = ENACT_SUCCESS;
            }
            else {
                if(verbose) printf("Invalid TPM magic value.\n");
            }
        }
        else {
            if(verbose) printf("Failure to process the new GPIO evidence.\n");
        }
    }
    else {
        if(verbose) printf("Failure to create GPIO evidence.\n");
        tpm_printError(verbose, ret);
    }

    return ret;
}
#endif /* ENACT_TPM_GPIO_ENABLE */

int tpm_get_ekcert(ENACT_TPM *tpm, const char *filename)
{
    int ret = ENACT_ERROR;
    NV_Read_In nvReadCmd;
    NV_Read_Out nvReadResp;
    NV_ReadPublic_In nvReadPubCmd;
    NV_ReadPublic_Out nvReadPubResp;
    word32 chunkSize, dataSize, readSize = 0;
    size_t fileSize;
    XFILE fp = NULL;

    /* nvReadPubCmd is just nvindex that we set below */
    XMEMSET(&nvReadCmd, 0, sizeof(nvReadCmd));
    XMEMSET(&nvReadResp, 0, sizeof(nvReadResp));
    nvReadPubCmd.nvIndex = TPM2_NV_ECC_EK_CERT;
    XMEMSET(&nvReadPubResp, 0, sizeof(nvReadPubResp));

    chunkSize = 512; /* Safe NV read step */
    if(verbose) printf("NVRead step is %d\n", chunkSize);

    ret = TPM2_NV_ReadPublic(&nvReadPubCmd, &nvReadPubResp);
    if(ret != TPM_RC_SUCCESS) {
        return ret;
    }
    printf("Found EKCert (%d bytes).\n", nvReadPubResp.nvPublic.nvPublic.dataSize);
    dataSize = nvReadPubResp.nvPublic.nvPublic.dataSize;

    /* Prepare file to store the EK Certificate */
    fp = XFOPEN(ENACT_EKCERT_FILENAME, "wt");
    if(fp == XBADFILE) {
        printf("Error creating a file to store the EK certificate\n");
        return ret;
    }

    /* Set Auth */
    wolfTPM2_SetAuthPassword(&tpm->dev, 0, NULL);
    wolfTPM2_UnsetAuth(&tpm->dev, 1);
    wolfTPM2_UnsetAuth(&tpm->dev, 2);

    /* Prepare NV Read command */
    nvReadCmd.authHandle = nvReadPubCmd.nvIndex;
    nvReadCmd.nvIndex = nvReadPubCmd.nvIndex;
    /* Read in steps from the TPM's NVRAM */
    while(dataSize != readSize) {
        nvReadCmd.offset = readSize;
        if(dataSize - readSize < chunkSize) {
            nvReadCmd.size = dataSize - readSize;
        }
        else {
            nvReadCmd.size = chunkSize;
        }

        ret = TPM2_NV_Read(&nvReadCmd, &nvReadResp);
        if(ret == TPM_RC_SUCCESS) {
            if(verbose) printf("NVRead %d bytes\n", nvReadResp.data.size);
            readSize += nvReadResp.data.size;
            fileSize = XFWRITE(nvReadResp.data.buffer, 1, nvReadResp.data.size, fp);
            if(fileSize != nvReadResp.data.size) {
                if(verbose) printf("Error while storing the EK Certificate\n");
                break;
            }
        }
        else {
            tpm_printError(verbose, ret);
            break;
        }
    }
    XFCLOSE(fp);

    if(dataSize == readSize) {
        ret = ENACT_SUCCESS;
        if(verbose) printf("Read EKCert of %d size\n", readSize);
    }
    return ret;
}

int tpm_get_property(ENACT_TPM *tpm, UINT32 tag, UINT32 *value)
{
    int ret = ENACT_SUCCESS;
    GetCapability_In cmdGetCap;
    GetCapability_Out respGetCap;

    cmdGetCap.capability = TPM_CAP_TPM_PROPERTIES;
    cmdGetCap.property = tag;
    cmdGetCap.propertyCount = 1; /* ask for one property */
    ret = TPM2_GetCapability(&cmdGetCap, &respGetCap);
    if(ret == TPM_RC_SUCCESS) {
        ret = ENACT_SUCCESS;
        printf("PT NV Read MAX is %d\n",
               respGetCap.capabilityData.data.tpmProperties.tpmProperty[0].value);
        *value = respGetCap.capabilityData.data.tpmProperties.tpmProperty[0].value;
    }
    else {
        printf("Failed to read TPM property\n");
    }

    return ret;
}
