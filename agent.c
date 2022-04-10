/* agent.c
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


#include "enact.h"
#include "tpm.h"
#include "misc.h"

#include <stdio.h>
#include <string.h>
#include <dirent.h>         /* readdir */
#include <sys/utsname.h>    /* uname */
#include <curl/curl.h>      /* libcurl */


int EnactAgent(ENACT_EVIDENCE *data, ENACT_FILES *files, ENACT_TPM *tpm, int onboard);

static char uid[UUID_V4_SIZE];
static char nodeid[UUID_V4_SIZE];

/* EnactTrust has four tiers:
 *
 * * Quick start - Basic attestation service for 1 node (this version).
 * * Developer   - Advanced attestation service for 5 nodes.
 * * Team        - Up to 5 Developers, each with 10 nodes.
 * * Enterprise  - Protecting IoT products during their entire lifecycle,
 *                 ZeroTrust security model for critical infrastructure,
 *                 available on premise and as a managed service.
 *
 * Contact us at info@enacttrust.com for more information.
 *
 * Note: Typically, the configuration of EnactTrust Agent application
 *       can be maintained by the EnactTrust Security Cloud, however
 *       for the purposes of Basic attestation this is not required.
 *
 */

#ifdef DEBUG_PRINTS
static int verbose = 1;
#else
static int verbose = 0;
#endif /* DEBUG_PRINTS */

static int read_nodeid(ENACT_EVIDENCE *evidence, const char *filename)
{
    int ret = ENACT_ERROR;

    if(evidence != NULL && filename != NULL) {
        XFILE fp = NULL;
        int len;

        fp = XFOPEN(filename, "rb");
        if(fp != XBADFILE) {
            len = XFREAD((byte*)&nodeid, 1, sizeof(nodeid), fp);
            if(len == sizeof(nodeid)) {
                misc_uuid_str2bin(nodeid, sizeof(nodeid), evidence->nodeid,
                                  sizeof(evidence->nodeid));
                ret = ENACT_SUCCESS;
            }
        }
    }
    else {
        ret = BAD_ARG;
    }

    return ret;
}

static int store_pem(ENACT_PEM *pem, const char *filename)
{
    int ret = ENACT_ERROR;

    if(pem != NULL && filename != NULL) {
        XFILE fp = NULL;

        fp = XFOPEN(filename, "wt");
        if(fp != XBADFILE) {
            size_t fileSize = XFWRITE(pem->key, 1, pem->size, fp);
            if(fileSize == pem->size) {
                if(verbose) printf("Successfully stored to %s.\n", filename);
                ret = ENACT_SUCCESS;
            }
            XFCLOSE(fp);
        }
    }
    else {
        ret = BAD_ARG;
    }

    return ret;
}

size_t pem_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    if(UUID_V4_SIZE == (size * nmemb)) {
        XFILE fp = NULL;

        /* Store for use in Evidence later */
        XMEMCPY((byte*)&nodeid, ptr, (size * nmemb));

        fp = XFOPEN(ENACT_NODEID_TEMPFILE, "wt");
        if(fp != XBADFILE) {
            size_t fileSize = XFWRITE(ptr, 1, (size * nmemb), fp);
            if(fileSize == size) {
                int i;
                printf("New NodeID is:\n");
                for(i=0;  i<nmemb; i++) {
                    putchar(ptr[i]);
                }
                putchar('\n');
                if(verbose) printf("Successfully stored nodeID.\n");
            }
            XFCLOSE(fp);
        }
    }

    return size * nmemb;
}

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    int i;
    printf("response body is:\n");
    for(i=0; i<nmemb; i++) {
        putchar(ptr[i]);
    }
    printf("\n");
    return size * nmemb;
}

/* Preparing the TPM and our keys for use */
int agent_prepare(ENACT_TPM *tpm)
{
    int ret = 0;

    if(tpm == NULL) {
        return BAD_ARG;
    }

    /* EK is created during tpm_init() */
    ret = tpm_init(tpm);
    if(ret == ENACT_SUCCESS) {
        ret = tpm_createSRK(tpm);
        if(ret == ENACT_SUCCESS) {
            ret = tpm_createAK(tpm);
        }
    }

    if(ret == ENACT_SUCCESS) {
        if(verbose) printf("TPM ready\n");
    }

    return ret == TPM_RC_SUCCESS ? ENACT_SUCCESS : ENACT_ERROR;
}

int agent_onboarding(CURL *curl, ENACT_TPM *tpm)
{
    int ret = ENACT_ERROR;
    ENACT_PEM pem;
    word32 pemSize = sizeof(pem.key);
    CURLcode res;
    curl_mime *form = NULL;
    curl_mimepart *field = NULL;

    ret = tpm_exportEccPubToPem(tpm, &pem, ENACT_AKPEM_FILENAME);
    if(ret == TPM_RC_SUCCESS) {
        store_pem(&pem, ENACT_AKPEM_FILENAME);
        if(verbose) printf("Agent sent onboarding information.\n");
    }

    ret = wolfTPM2_RsaKey_TpmToPemPub(&tpm->dev, &tpm->ek, pem.key, &pemSize);
    if(ret == TPM_RC_SUCCESS) {
        pem.size = pemSize;
        store_pem(&pem, ENACT_EKPEM_FILENAME);
        if(verbose) printf("Agent sent onboarding information.\n");
    }

    if(curl) {
        form = curl_mime_init(curl);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_PEM_ARG_AK);
        curl_mime_filedata(field, "ak.pem");

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_PEM_ARG_EK);
        curl_mime_filedata(field, "ek.pem");

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_PEM_ARG_AKNAME);
        curl_mime_data(field, (const char *)tpm->ak.handle.name.name,
                       tpm->ak.handle.name.size);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_PEM_ARG_UID);
        curl_mime_data(field, (const char *)uid, sizeof(uid));

        curl_easy_setopt(curl, CURLOPT_URL, URL_WEBTEST);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pem_callback);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }
        else {
            ret = ENACT_SUCCESS;
        }
    }

    curl_easy_reset(curl);
    curl_mime_free(form);
    return ret;
}

int agent_sentGolden(CURL *curl)
{
    int ret = ENACT_ERROR;
    CURLcode res;
    curl_mime *form = NULL;
    curl_mimepart *field = NULL;

    if(curl) {
        form = curl_mime_init(curl);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_GOLDEN_ARG_GOLDEN);
        curl_mime_filedata(field, ENACT_QUOTE_FILENAME);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_GOLDEN_ARG_SIGN);
        curl_mime_filedata(field, ENACT_SIGNATURE_FILENAME);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_GOLDEN_ARG_NODEID);
        curl_mime_filedata(field, ENACT_NODEID_TEMPFILE);

        curl_easy_setopt(curl, CURLOPT_URL, URL_WEBTEST);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }
        else {
            ret = ENACT_SUCCESS;
        }
    }

    curl_easy_reset(curl);
    curl_mime_free(form);
    return ret;
}

int agent_sentEvidence(CURL *curl)
{
    int ret = ENACT_ERROR;
    CURLcode res;
    curl_mime *form = NULL;
    curl_mimepart *field = NULL;

    if(curl) {
        form = curl_mime_init(curl);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_EVIDENCE_ARG_EVIDENCE);
        curl_mime_filedata(field, ENACT_QUOTE_FILENAME);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_EVIDENCE_ARG_SIGN);
        curl_mime_filedata(field, ENACT_SIGNATURE_FILENAME);

        field = curl_mime_addpart(form);
        curl_mime_name(field, ENACT_API_EVIDENCE_ARG_NODEID);
        curl_mime_filedata(field, ENACT_NODEID_TEMPFILE);

        curl_easy_setopt(curl, CURLOPT_URL, URL_WEBTEST);
        curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        }
        else {
            ret = ENACT_SUCCESS;
        }
    }

    curl_easy_reset(curl);
    curl_mime_free(form);
    return ret;
}

int fs_listFiles(ENACT_FILES *files)
{
    int i, ret = ENACT_ERROR;
    struct dirent *dir;
    DIR *d;

    files->count = 0;

    d = opendir(ENACT_DEMO_PATH);
    if(d != NULL) {
        if(verbose) printf("Listing all files in current directory\n");
        for(i = 0; i < MAX_FILE_COUNT; i++) {
            dir = readdir(d);
            if(dir == NULL) {
                if(verbose) printf("No more files in directory\n");
                break;
            }
            /* Interested only in regular files */
            if(dir->d_type == DT_REG) {
                if(verbose) printf("\tFound %s\n", dir->d_name);
                strncpy(files->name[i], ENACT_DEMO_PATH, sizeof(files->name[i]));
                strncat(files->name[i], dir->d_name, sizeof(files->name[i])-sizeof(ENACT_DEMO_PATH));
                files->count++;
            }
            else {
                if(verbose) printf("\tSkipping %s\n", dir->d_name);
                i--;
            }
        }
    }
    else {
        if(verbose) printf("Unable to open directory. Protecting /etc/passwd\n");
        /* Special case: protect Linux user list */
        strncpy(files->name[0], ENACT_DEMO_FILE, sizeof(files->name[0]));
        files->count++;
    }

    if(verbose) {
        printf("List of regular files(%d):\n", files->count);
        for(int i = 0; i < files->count; i++) {
           printf("%s \n", files->name[i]);
        }
    }

    if(files->count > 0) {
        ret = ENACT_SUCCESS;
    }

    return ret;
}


int fs_storeQuote(ENACT_EVIDENCE *evidence)
{
    int ret = ENACT_ERROR;
    int fileSize, retSize, expectedSize;
    FILE *fp;

    retSize = expectedSize = 0;
    fp = XFOPEN(ENACT_QUOTE_FILENAME, "wb");
    if(fp != XBADFILE) {
        fileSize = sizeof(evidence->raw.size);
        expectedSize = sizeof(evidence->raw.size);
        ret = XFWRITE((BYTE*)&evidence->raw.size, 1, fileSize, fp);
        retSize = ret;

        fileSize = (int)evidence->raw.size;
        expectedSize += evidence->raw.size;
        ret = XFWRITE(evidence->raw.attestationData, 1, fileSize, fp);
        retSize += ret;

        if(verbose) printf("store TPM2B_ATTEST total size = %d\n", expectedSize);
        XFCLOSE(fp);
    }
    else {
        if(verbose) printf("Unable to open file");
    }

    if(expectedSize == retSize) {
        if(verbose) printf("Evidence stored to file.\n");
        ret = ENACT_SUCCESS;
    }

    return ret;
}

int fs_storeSign(ENACT_EVIDENCE *evidence)
{
    UINT16 ret = ENACT_ERROR;
    UINT16 fileSize, retSize, expectedSize;
    BYTE *buffer = NULL;
    FILE *fp = NULL;

    retSize = expectedSize = 0;
    fp = XFOPEN(ENACT_SIGNATURE_FILENAME, "wb");
    if(fp != XBADFILE) {
        /* Store signature and hash algorithm */
        fileSize = sizeof(evidence->signature.sigAlg);
        expectedSize += fileSize;
        ret = XFWRITE(&evidence->signature.sigAlg, 1, fileSize, fp);
        retSize += ret;

        fileSize = sizeof(evidence->signature.signature.ecdsa.hash);
        expectedSize += fileSize;
        ret = XFWRITE(&evidence->signature.signature.ecdsa.hash, 1, fileSize, fp);
        retSize += ret;

        /* R part of ECC signature */
        fileSize = sizeof(evidence->signature.signature.ecdsa.signatureR.size);
        expectedSize += fileSize;
        ret = XFWRITE(&evidence->signature.signature.ecdsa.signatureR.size, 1, fileSize, fp);
        retSize += ret;

        buffer = evidence->signature.signature.ecdsa.signatureR.buffer;
        fileSize = evidence->signature.signature.ecdsa.signatureR.size;
        expectedSize += fileSize;
        ret = XFWRITE(buffer, 1, fileSize, fp);
        retSize += ret;
        /* S part of ECC signature */
        fileSize = sizeof(evidence->signature.signature.ecdsa.signatureS.size);
        expectedSize += fileSize;
        ret = XFWRITE(&evidence->signature.signature.ecdsa.signatureS.size, 1, fileSize, fp);
        retSize += ret;

        buffer = evidence->signature.signature.ecdsa.signatureS.buffer;
        fileSize = evidence->signature.signature.ecdsa.signatureS.size;
        expectedSize += fileSize;
        ret = XFWRITE(buffer, 1, fileSize, fp);
        retSize += ret;
        XFCLOSE(fp);
    }
    else {
        if(verbose) printf("Unable to open file");
    }

    if(expectedSize == retSize) {
        if(verbose) printf("Signature stored to file.\n");
        ret = ENACT_SUCCESS;
    }

    return ret;
}

int EnactAgent(ENACT_EVIDENCE *evidence, ENACT_FILES *files, ENACT_TPM *tpm, int onboard)
{
    int ret = ENACT_ERROR;
    CURL *curl;

    /* Gather the file paths for protection */
    ret = fs_listFiles(files);
    if(ret) {
        printf("Failed to acquire assets to protect\n");
    }
    /* Initialize our TPM keys */
    ret = agent_prepare(tpm);
    if(ret) {
        printf("Error while accessing the Security Chip\n");
    }
    /* Initialize libcurl (done only once) */
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(!curl) {
        printf("Unable to use libcurl, evidence will exist only locally\n");
    }

    if(onboard) {
        /* Send AK & EK PEM for host identification */
        agent_onboarding(curl, tpm);
    }
    else {
        /* Read nodeID to prepare for use later, in evidence */
        read_nodeid(evidence, ENACT_NODEID_TEMPFILE);
    }

    /* Evidence step */
    ret = tpm_pcrReset(ENACT_TPM_QUOTE_PCR);
    if(ret == ENACT_SUCCESS) {
        ret = tpm_pcrExtend(files, ENACT_TPM_QUOTE_PCR);
    }
    else {
        printf("Unable to prepare evidence\n");
    }

    if(ret == ENACT_SUCCESS) {
        /* Convert from string ot binary for use in Evidence later */
        misc_uuid_str2bin(nodeid, sizeof(nodeid), evidence->nodeid, sizeof(evidence->nodeid));
        /* Ask the TPM to prepare an evidence */
        ret = tpm_createQuote(tpm, evidence);
    }
    else {
        printf("Unable to create evidence\n");
    }
    /* Store temporary artifacts */
    if(ret == ENACT_SUCCESS) {
        printf("Storing quote\n");
        ret = fs_storeQuote(evidence);
        printf("Storing signature\n");
        ret |= fs_storeSign(evidence);
        if(ret) {
            printf("Failed to store evidence\n");
        }
    }
    /* Transfer golden or fresh evidence to the EnactTrust verifier */
    if(onboard) {
        agent_sentGolden(curl);
    }
    else {
        agent_sentEvidence(curl);
    }

    if(ret == ENACT_SUCCESS) {
        printf("OK. Evidence created and sent. No action required.\n");
    }
    else {
        printf("Error %d. Please contact us at support@enacttrust.com\n", ret);
    }

    /* Make sure we do a clean exit */
    if(curl) {
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    tpm_deinit(tpm);
    return ret;
}

void usage(void) {
    printf("EnactTrust agent has these modes of operation:\n");
    printf("\t./enact onboard UID - Use to provision a new node\n");
    printf("\t\tUID - Register at www.enacttrust.com for your user id.\n");
    printf("\t./enact start - EnactTrust is configured as a Linux service\n");
    printf("\t\tThis way Enact can continiously monitor the system health\n");
    printf("\t./enact - Generate a fresh evidence\n");
    printf("\t\tTypically, the Linux service generates the fresh evidence,\n");
    printf("\t\thowever, enact can be launched on demand for various use cases\n");
    printf("Please contact us at \"support@enacttrust.com\" for more information.\n");
}

void uid_usage(void) {
    printf("Onboarding requires a user id(UID). Example usage with UID:\n");
    printf("\n\t./enact onboard 68360761-b72f-4ba3-86c9-7156577a54da\n\n");
    printf("UID can be acquired by registering at www.enacttrust.com\n");
}

int main(int argc, char *argv[])
{
    int onboarding, setup, ret = ENACT_ERROR;
    ENACT_EVIDENCE evidence;
    ENACT_FILES files;
    ENACT_TPM tpm;

    XMEMSET(uid, 0, sizeof(uid));
    XMEMSET(nodeid, 0, sizeof(nodeid));

    /* Parse arguments */
    onboarding = setup = 0;
    if(argc >= 2) {
        if(XSTRNCMP(argv[1], "onboard", 7) == 0) {
            onboarding = 1;
            if(argc == 3) {
                strncpy(uid, argv[2], sizeof(uid));
            }
            else {
                uid_usage();
                return BAD_ARG;
            }
        }
        else if(XSTRNCMP(argv[1], "start", 5) == 0) {
            setup = 1;
        }
        else {
            usage();
            return BAD_ARG;
        }
    }
    else {
        if(verbose) printf("Generating fresh evidence.\n");
    }

    /* Configure as a service, or execute an action */
    if(setup) {
        printf("Running as a Linux service is not implemented\n");
        ret = NOT_IMPLEMENTED; /* TODO */
    }
    else {
        ret = EnactAgent(&evidence, &files, &tpm, onboarding);
    }

    return ret;
}
