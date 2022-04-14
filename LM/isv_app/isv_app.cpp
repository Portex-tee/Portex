/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server.

#include "ra.h"
#include "log.h"
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
// Needed for definition of remote attestation messages.
#include "remote_attestation_result.h"

#include "isv_enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"

// Needed to query extended epid group id.
#include "sgx_uae_service.h"

#include "service_provider.h"


// Needed to calculate keys

#include "aibe.h"

#define LENOFMSE 1024

#ifndef SAFE_FREE
#define SAFE_FREE(ptr)     \
    {                      \
        if (NULL != (ptr)) \
        {                  \
            free(ptr);     \
            (ptr) = NULL;  \
        }                  \
    }
#endif

// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"

#define ENCLAVE_PATH "isv_enclave.signed.so"

extern char sendbuf[BUFSIZ]; //数据传送的缓冲区
extern char recvbuf[BUFSIZ];

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x

int lm_keyreq(const std::string& srcStr, LogTree logTree, sgx_enclave_id_t enclave_id, FILE *OUTPUT, NetworkClient client) {

    int ret = 0;
    uint8_t data[BUFSIZ];
    Proofs proofs;
    std::string encodedHexStr;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int data_size, msg_size, recvlen;

    sha256(srcStr, encodedHexStr);
    ChronTreeT::Hash hash(encodedHexStr);
    logTree.append(hash, proofs);

    msg_size = proofs.serialise(data);
    p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg_size);
    p_request->type = TYPE_RA_KEYREQ;
    p_request->size = msg_size;

    // todo: encrypt/decrypt
    memcpy_s(p_request->body, msg_size, data, msg_size);

    if (memcpy_s(p_request->body, msg_size, data, msg_size)) {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s]-[%d].",
                __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }

    memset(client.sendbuf, 0, BUFSIZ);
    memcpy_s(client.sendbuf, BUFSIZ, p_request, sizeof(ra_samp_request_header_t) + msg_size);
    client.SendTo(sizeof(ra_samp_request_header_t) + p_request->size);

    recvlen = client.RecvFrom();
    p_response = (ra_samp_response_header_t *) malloc(sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) client.recvbuf)->size);

    if (memcpy_s(p_response, recvlen, client.recvbuf, recvlen)) {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s]-[%d].",
                __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }
    if ((p_response->type != TYPE_RA_KEYREQ)) {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - response type unmatched in [%s]-[%d].",
                __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }


    data_size = p_response->size;
    memcpy_s(data, data_size, p_response->body, data_size);

//    assert(proofs.path->verify(proofs.root));
    std::cout << "certificate received" << std::endl;

    CLEANUP:
    SAFE_FREE(p_request);
    return ret;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    sgx_enclave_id_t enclave_id = 0;
    FILE *OUTPUT = stdout;
    NetworkClient client;
    LogTree logTree;

    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
    {
        ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                                 SGX_DEBUG_FLAG,
                                 &launch_token,
                                 &launch_token_update,
                                 &enclave_id, NULL);
        if (SGX_SUCCESS != ret)
        {
            ret = -1;
            fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        fprintf(OUTPUT, "\nCall sgx_create_enclave success.");
    }

    // SOCKET: connect to server
    if (client.client("127.0.0.1", 12333) != 0)
    {
        fprintf(OUTPUT, "Connect Server Error, Exit!\n");
        ret = -1;
        goto CLEANUP;
    }


    if (remote_attestation(enclave_id, client) != SGX_SUCCESS)
    {
        fprintf(OUTPUT, "Remote Attestation Error, Exit!\n");
        ret = -1;
        goto CLEANUP;
    }

    lm_keyreq("message", logTree, enclave_id, OUTPUT, client);


//    aibeAlgo.run(OUTPUT);

    //aibe load_param

CLEANUP:
    terminate(client);
    client.Cleanupsocket();
    sgx_destroy_enclave(enclave_id);

    fprintf(OUTPUT, "\nSuccess Clean Up A-IBE ");

    return ret;
}
