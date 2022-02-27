/* tpm.h
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


int tpm_init(ENACT_TPM *tpm);
int tpm_deinit(ENACT_TPM *tpm);

int tpm_createEK(ENACT_TPM *tpm);
int tpm_createSRK(ENACT_TPM *tpm);
int tpm_createAK(ENACT_TPM *tpm);

int tpm_pcrReset(UINT32 pcrIndex);
int tpm_pcrRead(ENACT_EVIDENCE *tpm, UINT32 pcrIndex);
int tpm_pcrExtend(ENACT_FILES *files, UINT32 pcrIndex);

int tpm_createQuote(ENACT_TPM *tpm, ENACT_EVIDENCE *attested);

int tpm_exportEccPubToPem(ENACT_TPM *tpm, ENACT_PEM *pem, const char *filename);
int tpm_exportRsaPubToPem(ENACT_TPM *tpm, ENACT_PEM *pem, const char *filename);

inline void tpm_printError(int verbose, int ret)
{
    if(verbose) printf("TPM error 0x%x: %s\n", ret, TPM2_GetRCString(ret));
}

