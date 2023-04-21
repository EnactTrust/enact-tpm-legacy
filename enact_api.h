/* enact_api.h
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

#ifndef _ENACT_API_H_
#define _ENACT_API_H_

#ifdef __cplusplus
    extern "C" {
#endif

/* EnactTrust & Veraison API as decsribed in the api-integration UML diagram */
#define ENACT_API_PEM       "node/pem"
#define ENACT_API_SECRET    "node/secret"
#define ENACT_API_GOLDEN    "node/golden"
#define ENACT_API_EVIDENCE  "node/evidence"
#define ENACT_API_EKCERT    "node/tpmekcert"
#define ENACT_API_GPIOEVID  "node/tpmgpio"

#define ENACT_API_PEM_ARG_AK    "ak_pub"
#define ENACT_API_PEM_ARG_EK    "ek_pub"
#define ENACT_API_PEM_ARG_AKNAME "ak_name"
#define ENACT_API_PEM_ARG_EKCERT "ek_cert"
#define ENACT_API_PEM_ARG_UID   "user_id"
#define ENACT_API_PEM_ARG_HOSTNAME "hostname"

#define ENACT_API_GOLDEN_ARG_GOLDEN "golden_blob"
#define ENACT_API_GOLDEN_ARG_SIGN   "signature_blob"
#define ENACT_API_GOLDEN_ARG_NODEID "node_id"

#define ENACT_API_EVIDENCE_ARG_EVIDENCE "evidence_blob"
#define ENACT_API_EVIDENCE_ARG_SIGN     ENACT_API_GOLDEN_ARG_SIGN
#define ENACT_API_EVIDENCE_ARG_NODEID   ENACT_API_GOLDEN_ARG_NODEID


/* EnactTrust defines of endpoints */
#define URL_LOCALHOST   "http://localhost:8000/"
#define URL_LOCALHOST_NODE_PEM      URL_LOCALHOST ENACT_API_PEM
#define URL_LOCALHOST_NODE_GOLDEN   URL_LOCALHOST ENACT_API_GOLDEN
#define URL_LOCALHOST_NODE_EVIDENCE URL_LOCALHOST ENACT_API_EVIDENCE

#ifdef VERAISON_ENABLED
#define ENACT_BACKEND   URL_LOCALHOST
#else /* EnactTrust A3S */
#define ENACT_BACKEND   "https://api.enacttrust.com:8000/"
#endif

#define URL_BACKEND_NODE_PEM        ENACT_BACKEND ENACT_API_PEM
#define URL_BACKEND_NODE_GOLDEN     ENACT_BACKEND ENACT_API_GOLDEN
#define URL_BACKEND_NODE_EVIDENCE   ENACT_BACKEND ENACT_API_EVIDENCE
#define URL_BACKEND_NODE_EKCERT     ENACT_BACKEND ENACT_API_EKCERT
#define URL_BACKEND_NODE_GPIOEVID   ENACT_BACKEND ENACT_API_GPIOEVID

/* Endpoints in use */
#define URL_NODE_PEM        URL_BACKEND_NODE_PEM
#define URL_NODE_GOLDEN     URL_BACKEND_NODE_GOLDEN
#define URL_NODE_EVIDENCE   URL_BACKEND_NODE_EVIDENCE
#define URL_NODE_EKCERT     URL_BACKEND_NODE_EKCERT
#define URL_NODE_GPIOEVID   URL_BACKEND_NODE_GPIOEVID

#ifdef __cplusplus
    }
#endif

#endif /* _ENACT_API_H_ */
