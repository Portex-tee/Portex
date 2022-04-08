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

int main(int argc, char *argv[])
{
    int ret = 0;
    sgx_enclave_id_t enclave_id = 0;
    AibeAlgo aibeAlgo;
    sgx_aes_gcm_128bit_tag_t mac;

    int data_len;
    uint8_t data[1024];
    uint8_t encrypt_data[1024];
    uint8_t decrypt_data[1024];
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

////    aibe: keygen1

    aibeAlgo.keygen1(ID);

    ra_samp_request_header_t requestHeader;
    ra_samp_response_header_t responseHeader;

//    data_len = element_length_in_bytes(aibeAlgo.R);
//    printf("R in length: %d\n", aibeAlgo.size_comp_G1);
//    element_printf("R: \n%B\n", aibeAlgo.R);
//
//    element_to_bytes_compressed(data, aibeAlgo.R);
//
//    puts("ra_encrypt start===");
//    ra_encrypt(data, data_len, encrypt_data, mac, enclave_id, OUTPUT);
//    PRINT_BYTE_ARRAY(OUTPUT, encrypt_data, data_len);
//
//    puts("ra_decrypt start===");
//    ra_decrypt(encrypt_data, data_len, decrypt_data, mac, enclave_id, OUTPUT);
//    PRINT_BYTE_ARRAY(OUTPUT, decrypt_data, data_len);
//
//    element_from_bytes_compressed(aibeAlgo.R, decrypt_data);
//    data_len = element_length_in_bytes(aibeAlgo.R);
//    puts("After encrypt and decrypt:");
//    printf("R in length: %d\n", data_len);
//    element_printf("R: \n%B\n", aibeAlgo.R);

    fprintf(OUTPUT, "\nA-IBE Success Keygen1 ");

////    todo: server aibe keygen2
    aibeAlgo.keygen2();
    puts("\nPKG: keygen2 finished");

////    aibe: keygen3
    if (aibeAlgo.keygen3()) {
        fprintf(stderr, "\nKey verify failed");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "\nA-IBE Success Keygen3 ");
    //todo: aibe clear

CLEANUP:
    Cleanupsocket();
    sgx_destroy_enclave(enclave_id);

    aibeAlgo.clear();
    fprintf(OUTPUT, "\nSuccess Clean Up A-IBE ");

    return ret;
}
