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


int client_keygen(int id, AibeAlgo aibeAlgo, sgx_enclave_id_t enclave_id, FILE *OUTPUT) {
    int ret = 0;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int recvlen = 0;
    int busy_retry_time;
    int data_size;
    int msg_size;

    uint8_t p_data[LENOFMSE] = {0};
    uint8_t out_data[LENOFMSE] = {0};
    sgx_aes_gcm_128bit_tag_t mac;

    // keygen 1
    aibeAlgo.keygen1(id);

    data_size = aibeAlgo.size_comp_G1 * 2;
    element_to_bytes_compressed(p_data, aibeAlgo.R);
    element_to_bytes_compressed(p_data + aibeAlgo.size_comp_G1, aibeAlgo.Hz);
    ra_encrypt(p_data, data_size, out_data, mac, enclave_id, OUTPUT);

    element_fprintf(OUTPUT, "\nSend R:\n%B", aibeAlgo.R);

    msg_size = data_size + SGX_AESGCM_MAC_SIZE;
    p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg_size);
    p_request->size = msg_size;
    p_request->type = TYPE_RA_KEYGEN;

    if (memcpy_s(p_request->body, data_size, out_data, data_size)) {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s]-[%d].",
                __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }
    if (memcpy_s(p_request->body + data_size, SGX_AESGCM_MAC_SIZE, mac, SGX_AESGCM_MAC_SIZE)) {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s]-[%d].",
                __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }

    memset(sendbuf, 0, BUFSIZ);
    memcpy_s(sendbuf, BUFSIZ, p_request, sizeof(ra_samp_request_header_t) + msg_size);
    SendToServer(sizeof(ra_samp_request_header_t) + p_request->size);

    // keygen 3
    recvlen = RecvfromServer();
    p_response = (ra_samp_response_header_t *) malloc(sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) recvbuf)->size);

    if (memcpy_s(p_response, recvlen, recvbuf, recvlen)) {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s]-[%d].",
                __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }
    if ((p_response->type != TYPE_RA_KEYGEN)) {
        fprintf(OUTPUT, "\nError: INTERNAL ERROR - memcpy failed in [%s]-[%d].",
                __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }

    data_size = p_response->size - SGX_AESGCM_MAC_SIZE;

    memcpy_s(p_data, data_size, p_response->body, data_size);
    memcpy_s(mac, SGX_AESGCM_MAC_SIZE, p_response->body + data_size, SGX_AESGCM_MAC_SIZE);
//    fprintf(OUTPUT, "\nSuccess Encrypt\n");
//    PRINT_BYTE_ARRAY(OUTPUT, p_data, sizeof(p_data));
//    fprintf(OUTPUT, "\nEncrypt Mac\n");
//    PRINT_BYTE_ARRAY(OUTPUT, mac, SGX_AESGCM_MAC_SIZE);

    ra_decrypt(p_data, data_size, out_data, mac, enclave_id, OUTPUT);

    dk_from_bytes(&aibeAlgo.dk1, out_data, aibeAlgo.size_comp_G1);
    {
        fprintf(stdout, "\nData of dk' is\n");
        element_fprintf(stdout, "dk'.d1: %B\n", aibeAlgo.dk1.d1);
        element_fprintf(stdout, "dk'.d2: %B\n", aibeAlgo.dk1.d2);
        element_fprintf(stdout, "dk'.d3: %B\n", aibeAlgo.dk1.d3);
    }

    if (aibeAlgo.keygen3()) {
        ret = -1;
        goto CLEANUP;
    }

    {
        fprintf(stdout, "\nData of dk is\n");
        element_fprintf(stdout, "dk.d1: %B\n", aibeAlgo.dk.d1);
        element_fprintf(stdout, "dk.d2: %B\n", aibeAlgo.dk.d2);
        element_fprintf(stdout, "dk.d3: %B\n", aibeAlgo.dk.d3);
    }

    CLEANUP:
    SAFE_FREE(p_response);
    return ret;
}

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x

int main(int argc, char *argv[])
{
    int ret = 0;
    sgx_enclave_id_t enclave_id = 0;
    AibeAlgo aibeAlgo;
    FILE *OUTPUT = stdout;


    //aibe load_param
    pairing_t pairing;
    char param[1024];
    FILE *param_file = fopen(param_path, "r");
    size_t count = fread(param, sizeof(char), 1024, param_file);
    if (!count) {
        pbc_die("param file path error");
    }
    pairing_init_set_buf(pairing, param, count);

    fprintf(OUTPUT, "\nA-IBE Success Set Up");


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


    // todo: mpk load_param

    fprintf(OUTPUT, "\nA-IBE Success Init ");

    // SOCKET: connect to server
    if (remote_attestation(enclave_id, "127.0.0.1", 12333) != SGX_SUCCESS)
    {
        fprintf(OUTPUT, "Remote Attestation Error, Exit!\n");
        return -1;
    }


//    aibeAlgo.run(OUTPUT);

    //aibe load_param

    if (aibeAlgo.load_param(param_path)) {
        ret = -1;
        fprintf(stderr, "\nParam File Path error");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "\nA-IBE Success Set Up");

////    element init
    aibeAlgo.init();

////    todo: server aibe load_param
    aibeAlgo.mpk_load();

    puts("\nPKG: setup finished");

////    aibe: keygen
    if (client_keygen(ID, aibeAlgo, enclave_id, OUTPUT)) {
        fprintf(stderr, "\nKey verify failed");
        goto CLEANUP;
    }
    fprintf(OUTPUT, "\nA-IBE Success Keygen ");

CLEANUP:
    Cleanupsocket();
    sgx_destroy_enclave(enclave_id);

    aibeAlgo.clear();
    fprintf(OUTPUT, "\nSuccess Clean Up A-IBE ");

    return ret;
}
