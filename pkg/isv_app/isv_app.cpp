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

#include "log.h"
#include "aibe.h"
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <json.hpp>
#include <vector>
#include "ec_crypto.h"

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

#define _T(x) x
// In addition to generating and sending messages, this application
// can use pre-generated messages to verify the generation of
// messages and the information flow.
#include "sample_messages.h"

#define ENCLAVE_PATH "isv_enclave.signed.so"

#define LENOFMSE 1024

#define debug_enable (1)  //1---open   0---close

#define DBG(...) if(debug_enable)(fprintf(__VA_ARGS__))
#define ELE_DBG(...) if(debug_enable)(element_fprintf(__VA_ARGS__))

using json = nlohmann::json;

int rbits = 160;
int qbits = (1 << 8); // lambda

uint8_t *msg1_samples[] = {msg1_sample1, msg1_sample2};
uint8_t *msg2_samples[] = {msg2_sample1, msg2_sample2};
uint8_t *msg3_samples[] = {msg3_sample1, msg3_sample2};
uint8_t *attestation_msg_samples[] =
        {attestation_msg_sample1, attestation_msg_sample2};

// Some utility functions to output some of the data structures passed between
// the ISV app and the remote attestation service provider.
void PRINT_BYTE_ARRAY(FILE *file, void *mem, uint32_t len) {
    if (!mem || !len) {
        DBG(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *) mem;
    DBG(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for (i = 0; i < len - 1; i++) {
        DBG(file, "0x%x, ", array[i]);
        if (i % 8 == 7)
            DBG(file, "\n");
    }
    DBG(file, "0x%x ", array[i]);
    DBG(file, "\n}\n");
}

void PRINT_ATTESTATION_SERVICE_RESPONSE(
        FILE *file,
        ra_samp_response_header_t *response) {
    if (!response) {
        DBG(file, "\t\n( null )\n");
        return;
    }

    DBG(file, "RESPONSE TYPE:   0x%x\n", response->type);
    DBG(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    DBG(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if (response->type == TYPE_RA_MSG2) {
        sgx_ra_msg2_t *p_msg2_body = (sgx_ra_msg2_t *) (response->body);

        DBG(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        DBG(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        DBG(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        DBG(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        DBG(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        DBG(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        DBG(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    } else if (response->type == TYPE_RA_ATT_RESULT) {
        sample_ra_att_result_msg_t *p_att_result =
                (sample_ra_att_result_msg_t *) (response->body);
        DBG(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        DBG(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        DBG(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        DBG(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                         p_att_result->secret.payload_size);
    } else {
        DBG(file, "\nERROR in printing out the response. "
                      "Response of type not supported %d\n",
                response->type);
    }
}

int myaesencrypt(const ra_samp_request_header_t *p_msgenc,
                 uint32_t msg_size,
                 sgx_enclave_id_t id,
                 sgx_status_t *status,
                 sgx_ra_context_t context,
                 NetworkServer &server) {
    if (!p_msgenc || msg_size > LENOFMSE) {
        return -1;
    }
    int ret = 0;

    int data_size = msg_size;
    int busy_retry_time = 4;
    uint8_t p_data[LENOFMSE] = {0};
    uint8_t out_data[LENOFMSE] = {0};
    ra_samp_response_header_t *p_msg2_full = NULL;
    uint8_t msg2_size = data_size + SGX_AESGCM_MAC_SIZE;

    sgx_aes_gcm_128bit_tag_t mac;

    memcpy(p_data, p_msgenc, data_size);
    do {
        ret = enclave_encrypt(
                id,
                status,
                p_data,
                data_size,
                out_data,
                mac);
        DBG(stdout, "\nE %d %d", id, *status);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    DBG(stdout, "\nData of Encrypt is\n");
    PRINT_BYTE_ARRAY(stdout, p_data, data_size);
    DBG(stdout, "\nData of Encrypted and mac is\n");
    PRINT_BYTE_ARRAY(stdout, out_data, data_size);
    PRINT_BYTE_ARRAY(stdout, mac, SGX_AESGCM_MAC_SIZE);
    p_msg2_full = (ra_samp_response_header_t *) malloc(msg2_size + sizeof(ra_samp_response_header_t));
    if (!p_msg2_full) {
        DBG(stderr, "\nError, out of memory in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }
    memset(p_msg2_full, 0, msg2_size + sizeof(ra_samp_response_header_t));
    p_msg2_full->type = TYPE_RA_MSGENC;
    p_msg2_full->size = msg2_size;
    p_msg2_full->status[0] = 0;
    p_msg2_full->status[1] = 0;

    memcpy(p_msg2_full->body, out_data, data_size);
    memcpy(p_msg2_full->body + data_size, mac, SGX_AESGCM_MAC_SIZE);
    memset(server.sendbuf, 0, BUFSIZ);
    memcpy(server.sendbuf,
                 p_msg2_full,
                 msg2_size + sizeof(ra_samp_response_header_t));

    if (server.SendTo(msg2_size + sizeof(ra_samp_response_header_t)) < 0) {
        DBG(stderr, "\nError, send encrypted data failed in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }
    SAFE_FREE(p_msg2_full);

    return ret;
}

int myaesdecrypt(const ra_samp_request_header_t *p_msgenc,
                 uint32_t msg_size,
                 sgx_enclave_id_t id,
                 sgx_status_t *status,
                 sgx_ra_context_t context,
                 NetworkServer &server) {
    if (!p_msgenc ||
        (msg_size > LENOFMSE)) {
        return -1;
    }
    sgx_aes_gcm_128bit_tag_t mac;
    int ret = 0;
    DBG(stdout, "\nD %d %d", id, *status);
    int busy_retry_time = 4;
    uint8_t p_data[LENOFMSE] = {0};
    uint8_t out_data[LENOFMSE] = {0};
    ra_samp_response_header_t *p_msg2_full = NULL;
    uint8_t data_size = msg_size - SGX_AESGCM_MAC_SIZE;
    uint8_t msg2_size = data_size;

    DBG(stdout, "====%d %d\n", data_size, msg_size);
    PRINT_BYTE_ARRAY(stdout, (uint8_t *) p_msgenc, msg_size);

    memcpy(p_data, p_msgenc, msg_size);
    memcpy(mac, p_data + data_size, SGX_AESGCM_MAC_SIZE);
    do {
        ret = enclave_decrypt(
                id,
                status,
                p_data,
                data_size,
                out_data,
                mac);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if (ret != SGX_SUCCESS)
        return ret;
    DBG(stdout, "\nData of Decrypt and mac is\n");
    PRINT_BYTE_ARRAY(stdout, p_data, data_size);
    PRINT_BYTE_ARRAY(stdout, mac, SGX_AESGCM_MAC_SIZE);
    DBG(stdout, "\nData of Decrypted is\n");
    PRINT_BYTE_ARRAY(stdout, out_data, data_size);

    p_msg2_full = (ra_samp_response_header_t *) malloc(msg2_size + sizeof(ra_samp_response_header_t));
    if (!p_msg2_full) {
        DBG(stderr, "\nError, out of memory in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }
    memset(p_msg2_full, 0, msg2_size + sizeof(ra_samp_response_header_t));
    p_msg2_full->type = TYPE_RA_MSGDEC;
    p_msg2_full->size = msg2_size;
    // The simulated message2 always passes.  This would need to be set
    // accordingly in a real service provider implementation.
    p_msg2_full->status[0] = 0;
    p_msg2_full->status[1] = 0;

    memcpy(&p_msg2_full->body[0], &out_data[0], msg2_size);
    memset(server.sendbuf, 0, BUFSIZ);
    memcpy(server.sendbuf,
                 p_msg2_full,
                 msg2_size + sizeof(ra_samp_response_header_t));

    if (server.SendTo(msg2_size + sizeof(ra_samp_response_header_t)) < 0) {
        DBG(stderr, "\nError, send encrypted data failed in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }
    SAFE_FREE(p_msg2_full);
    DBG(stdout, "\nSend Decrypt Data Done.");
    return ret;
}

int pkg_keyreq(const uint8_t *p_msg,
               uint32_t msg_size,
               sgx_enclave_id_t id,
               sgx_status_t *status,
               AibeAlgo &aibeAlgo,
               NetworkServer &server) {
    std::vector<uint8_t> vec_prf, vec_pms;
    if (!p_msg ||
        (msg_size > BUFSIZ)) {
        return -1;
    }
    int ret = 0, res = 0;
    uint8_t data[BUFSIZ];
    Proofs proofs;
    int msg2_size;
    ra_samp_response_header_t *p_response = NULL;

    int busy_retry_time = 4;
    uint8_t p_data[LENOFMSE] = {0};
    uint8_t out_data[LENOFMSE] = {0};
    ra_samp_response_header_t *p_msg2_full = NULL;
    uint32_t data_size = msg_size - SGX_AESGCM_MAC_SIZE;

    std::vector<uint8_t> ir_sig, ir;


    // parse msg body to json
    json j_body, j_ir;
    {
        std::string msg_body((char *) p_msg);
        std::cout << msg_body << std::endl;
        j_body = json::parse(msg_body);
    }
    j_body.at("ir").get_to(j_ir);
    j_body.at("ir_sig").get_to(ir_sig);

    ir = json::to_bjdata(j_ir);
    res = ecdsa_verify(ir, ir_sig, "param/lm-verify.pem");

    j_ir.at("prf").get_to(vec_prf);
    j_ir.at("pms").get_to(vec_pms);

    std::copy(vec_prf.begin(), vec_prf.end(), data);
    DBG(stderr, "\nstart deserialise");
    proofs.deserialise(data);
    if (!proofs.verify_proofs()) {
        DBG(stderr, "\nProofs verify failed.");
    }
    DBG(stderr, "\nProofs verify succeed.");

    std::copy(vec_pms.begin(), vec_pms.end(), p_data);
    element_from_bytes_compressed(aibeAlgo.R, p_data);
    element_from_bytes_compressed(aibeAlgo.Hz, p_data + aibeAlgo.size_comp_G1);

    {
        DBG(stdout, "\nData of Hz and R is\n");
        ELE_DBG(stdout, "Hz: %B\n", aibeAlgo.Hz);
        ELE_DBG(stdout, "R: %B\n", aibeAlgo.R);
    }

    aibeAlgo.keygen2();

    {
        DBG(stdout, "\nData of dk' is\n");
        ELE_DBG(stdout, "dk'.d1: %B\n", aibeAlgo.dk1.d1);
        ELE_DBG(stdout, "dk'.d2: %B\n", aibeAlgo.dk1.d2);
        ELE_DBG(stdout, "dk'.d3: %B\n", aibeAlgo.dk1.d3);
    }

    dk_to_bytes(p_data, &aibeAlgo.dk1, aibeAlgo.size_comp_G1);
    data_size = aibeAlgo.size_comp_G1 * 2 + aibeAlgo.size_Zr;
    std::vector<uint8_t> vec_pkey(p_data, p_data + data_size), vec_pkey_sig, vec_ct;

    ecc_encrypt(vec_pkey, vec_ct, "param/client-pk.pem");
    ecdsa_sign(vec_ct, vec_pkey_sig, "param/pkg-sign.pem");

    json j_res{
            {"pkey_ct", vec_ct},
            {"sig",  vec_pkey_sig}
    };
    std::string msg_body = j_res.dump();

    msg2_size = msg_body.size() + 1;
    p_response = (ra_samp_response_header_t *) malloc(msg2_size + sizeof(ra_samp_response_header_t));
    if (!p_response) {
        DBG(stderr, "\nError, out of memory in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }

    // construct response
    memset(p_response, 0, msg2_size + sizeof(ra_samp_response_header_t));
    p_response->type = TYPE_RA_KEYREQ;
    p_response->size = msg2_size;
    p_response->status[0] = 0;
    p_response->status[1] = 0;
    strcpy((char *)p_response->body, msg_body.c_str());

    if (!res) {
        p_response->size = 0;
        p_response->status[1] = 1;
    }

// send to LM
    memset(server.sendbuf, 0, BUFSIZ);
    memcpy(server.sendbuf, p_response, msg2_size + sizeof(ra_samp_response_header_t));

    if (server.SendTo(msg2_size + sizeof(ra_samp_response_header_t)) < 0) {
        DBG(stderr, "\nError, send encrypted data failed in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }

    DBG(stdout, "\nKeyreq Done.");
    return ret;
}

int pkg_keygen(const ra_samp_request_header_t *p_msg,
               uint32_t msg_size,
               sgx_enclave_id_t id,
               sgx_status_t *status,
               AibeAlgo aibeAlgo,
               NetworkServer &server) {
    if (!p_msg ||
        (msg_size > LENOFMSE)) {
        return -1;
    }
    sgx_aes_gcm_128bit_tag_t mac;
    int ret = 0;
    int busy_retry_time = 4;
    int msg2_size = aibeAlgo.size_comp_G1 * 2 + aibeAlgo.size_Zr + SGX_AESGCM_MAC_SIZE;
    uint8_t p_data[LENOFMSE] = {0};
    uint8_t out_data[LENOFMSE] = {0};
    ra_samp_response_header_t *p_msg2_full = NULL;
    uint32_t data_size = msg_size - SGX_AESGCM_MAC_SIZE;

    memcpy(p_data, p_msg, msg_size);
    memcpy(mac, p_data + data_size, SGX_AESGCM_MAC_SIZE);
    do {
        ret = enclave_decrypt(
                id,
                status,
                p_data,
                data_size,
                out_data,
                mac);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);
    if (ret != SGX_SUCCESS)
        return ret;
//    std::cout << "data_size and msg_size are " << data_size << " and " << (int)msg_size << std::endl;
//    DBG(stdout, "\nData of Encrypted R and its MAC is\n");
//    PRINT_BYTE_ARRAY(stdout, p_data, data_size);
//    PRINT_BYTE_ARRAY(stdout, mac, SGX_AESGCM_MAC_SIZE);

    element_from_bytes_compressed(aibeAlgo.R, out_data);
    element_from_bytes_compressed(aibeAlgo.Hz, out_data + aibeAlgo.size_comp_G1);

    {
        DBG(stdout, "\nData of Hz and R is\n");
        ELE_DBG(stdout, "Hz: %B\n", aibeAlgo.Hz);
        ELE_DBG(stdout, "R: %B\n", aibeAlgo.R);
    }

    aibeAlgo.keygen2();

    {
        DBG(stdout, "\nData of dk' is\n");
        ELE_DBG(stdout, "dk'.d1: %B\n", aibeAlgo.dk1.d1);
        ELE_DBG(stdout, "dk'.d2: %B\n", aibeAlgo.dk1.d2);
        ELE_DBG(stdout, "dk'.d3: %B\n", aibeAlgo.dk1.d3);
    }

    busy_retry_time = 4;
    dk_to_bytes(p_data, &aibeAlgo.dk1, aibeAlgo.size_comp_G1);
    data_size = msg2_size - SGX_AESGCM_MAC_SIZE;
    do {
        ret = enclave_encrypt(
                id,
                status,
                p_data,
                data_size,
                out_data,
                mac);
    } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

    p_msg2_full = (ra_samp_response_header_t *) malloc(msg2_size + sizeof(ra_samp_response_header_t));
    if (!p_msg2_full) {
        DBG(stderr, "\nError, out of memory in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }
    memset(p_msg2_full, 0, msg2_size + sizeof(ra_samp_response_header_t));
    p_msg2_full->type = TYPE_RA_KEYGEN;
    p_msg2_full->size = msg2_size;
    p_msg2_full->status[0] = 0;
    p_msg2_full->status[1] = 0;

    memcpy(p_msg2_full->body, out_data, data_size);
    memcpy(p_msg2_full->body + data_size, mac, SGX_AESGCM_MAC_SIZE);
    memset(server.sendbuf, 0, BUFSIZ);
    memcpy(server.sendbuf,
                 p_msg2_full,
                 msg2_size + sizeof(ra_samp_response_header_t));

    if (server.SendTo(msg2_size + sizeof(ra_samp_response_header_t)) < 0) {
        DBG(stderr, "\nError, send encrypted data failed in [%s]-[%d].", __FUNCTION__, __LINE__);
        ret = SP_INTERNAL_ERROR;
        return ret;
    }

    SAFE_FREE(p_msg2_full);
    DBG(stdout, "\nKeygen2 Done.");
    return ret;
}


int main(int argc, char *argv[]) {
    int ret = 0;
    NetworkServer server;
    AibeAlgo aibeAlgo;
    ra_samp_request_header_t *p_msg0_full = NULL;
    ra_samp_response_header_t *p_msg0_resp_full = NULL;
    ra_samp_request_header_t *p_msg1_full = NULL;
    ra_samp_response_header_t *p_msg2_full = NULL;
    sgx_ra_msg3_t *p_msg3 = NULL;
    ra_samp_response_header_t *p_att_result_msg_full = NULL;
    sgx_enclave_id_t enclave_id = 0;
    int enclave_lost_retry_time = 1;
    int busy_retry_time = 4;
    sgx_ra_context_t context = INT_MAX;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t *p_msg3_full = NULL;
    ra_samp_request_header_t *p_msgaes_full = NULL;

    int32_t verify_index = -1;
    int32_t verification_samples = sizeof(msg1_samples) / sizeof(msg1_samples[0]);

    FILE *OUTPUT = stdout;
    ra_samp_request_header_t *p_req;
    ra_samp_response_header_t **p_resp;
    ra_samp_response_header_t *p_resp_msg;
    int server_port = 12333;
    int buflen = 0;
    uint32_t extended_epid_group_id = 0;


    {
        const char client_path[] = "../client/param/aibe.param";

        FILE *file_pkg = fopen(param_path, "w+");
        FILE *file_client = fopen(client_path, "w+");

        pbc_param_t p;
        pbc_param_init_a_gen(p, rbits, qbits);
        pbc_param_out_str(file_pkg, p);
        pbc_param_out_str(file_client, p);

        fclose(file_pkg);
        fclose(file_client);
    }


    if (1)
    {
        std::cout << "Generated pkg (vk, sk)" << std::endl;
        ecdsa_kgen("../client/param/pkg-verify.pem", "param/pkg-sign.pem");
    }

    aibeAlgo.load_param(param_path);
    puts("param loaded");
    aibeAlgo.init();
    puts("init");

    aibeAlgo.pkg_setup_generate();

    {
//        copy mpk to client
        const char client_mpk_path[] = "../client/param/mpk.out";
        char buff[256];
        sprintf(buff, "cp %s %s", mpk_path, client_mpk_path);
        system(buff);
    }

    aibeAlgo.mpk_load();
    aibeAlgo.msk_load();
    puts("mpk loaded");

//    aibeAlgo.run(OUTPUT);

    { // creates the cryptserver enclave.

        ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
        if (SGX_SUCCESS != ret) {
            ret = -1;
            DBG(OUTPUT, "\nError, call sgx_get_extended_epid_group_id fail [%s].",
                    __FUNCTION__);
            return ret;
        }
        DBG(OUTPUT, "\nCall sgx_get_extended_epid_group_id success.");

        int launch_token_update = 0;
        sgx_launch_token_t launch_token = {0};
        memset(&launch_token, 0, sizeof(sgx_launch_token_t));
        do {
            ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                                     SGX_DEBUG_FLAG,
                                     &launch_token,
                                     &launch_token_update,
                                     &enclave_id, NULL);
            if (SGX_SUCCESS != ret) {
                ret = -1;
                DBG(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
                        __FUNCTION__);
                goto CLEANUP;
            }
            DBG(OUTPUT, "\nCall sgx_create_enclave success.");

            ret = enclave_init_ra(enclave_id,
                                  &status,
                                  false,
                                  &context);
            //Ideally, this check would be around the full attestation flow.
        } while (SGX_ERROR_ENCLAVE_LOST == ret && enclave_lost_retry_time--);

        if (SGX_SUCCESS != ret || status) {
            ret = -1;
            DBG(OUTPUT, "\nError, call enclave_init_ra fail [%s].",
                    __FUNCTION__);
            goto CLEANUP;
        }
        DBG(OUTPUT, "\nCall enclave_init_ra success.");
    }

    //服务进程，对接受的数据进行响应
    DBG(OUTPUT, "\nstart socket....");
    server.server(server_port);

    //如果接受的信息类型为服务类型，就解析
    do {
        bool is_recv = true;
        do {
            //阻塞调用socket
            buflen = server.RecvFrom();
            if (buflen > 0 && buflen < BUFSIZ) {
                p_req = (ra_samp_request_header_t *) malloc(buflen + 2);

                DBG(OUTPUT, "\nPrepare receive struct");
                if (NULL == p_req) {
                    ret = -1;
                    goto CLEANUP;
                }
                memcpy(p_req, server.recvbuf, buflen);
                DBG(OUTPUT, "\nrequest type is %d", p_req->type);
                switch (p_req->type) {
                    case TYPE_EXIT:
                        DBG(OUTPUT, "\nConnection terminated");
                        SAFE_FREE(p_req);
                        is_recv = false;
                        break;
                        //收取msg1，进行验证并返回msg2
                    //收取msg0，进行验证
                    case TYPE_RA_MSG0:
                        DBG(OUTPUT, "\nProcess Message 0");
                        ret = sp_ra_proc_msg0_req(
                                (const sample_ra_msg0_t *) ((uint8_t *) p_req + sizeof(ra_samp_request_header_t)),
                                p_req->size);
                        DBG(OUTPUT, "\nProcess Message 0 Done");
                        if (0 != ret) {
                            DBG(OUTPUT, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                                    __FUNCTION__);
                        }
                        SAFE_FREE(p_req);
                        break;
                        //收取msg1，进行验证并返回msg2
                    case TYPE_RA_MSG1:
                        DBG(OUTPUT, "\nBuffer length is %d\n", buflen);
                        p_resp_msg = (ra_samp_response_header_t *) malloc(sizeof(ra_samp_response_header_t) + 170);//简化处理
                        memset(p_resp_msg, 0, sizeof(ra_samp_response_header_t) + 170);
                        DBG(OUTPUT, "\nProcess Message 1\n");
                        ret = sp_ra_proc_msg1_req(
                                (const sample_ra_msg1_t *) ((uint8_t *) p_req + sizeof(ra_samp_request_header_t)),
                                p_req->size,
                                &p_resp_msg);
                        DBG(OUTPUT, "\nProcess Message 1 Done");
                        if (0 != ret) {
                            DBG(stderr, "\nError, call sp_ra_proc_msg1_req fail [%s].",
                                    __FUNCTION__);
                        } else {
                            memset(server.sendbuf, 0, BUFSIZ);
                            memcpy(server.sendbuf, p_resp_msg,
                                         sizeof(ra_samp_response_header_t) + p_resp_msg->size);
                            DBG(OUTPUT, "\nSend Message 2\n");
                            PRINT_BYTE_ARRAY(OUTPUT, p_resp_msg, 176);
                            int buflen = server.SendTo(sizeof(ra_samp_response_header_t) + p_resp_msg->size);
                            DBG(OUTPUT, "\nSend Message 2 Done,send length = %d", buflen);
                        }
                        SAFE_FREE(p_req);
                        SAFE_FREE(p_resp_msg);
                        break;
                        //收取msg3，返回attestation result
                    case TYPE_RA_MSG3:
                        DBG(OUTPUT, "\nProcess Message 3");
                        p_resp_msg = (ra_samp_response_header_t *) malloc(sizeof(ra_samp_response_header_t) + 200);//简化处理
                        memset(p_resp_msg, 0, sizeof(ra_samp_response_header_t) + 200);
                        ret = sp_ra_proc_msg3_req((const sample_ra_msg3_t *) ((uint8_t *) p_req +
                                                                              sizeof(ra_samp_request_header_t)),
                                                  p_req->size,
                                                  &p_resp_msg);
                        if (0 != ret) {
                            DBG(stderr, "\nError, call sp_ra_proc_msg3_req fail [%s].",
                                    __FUNCTION__);
                        } else {
                            memset(server.sendbuf, 0, BUFSIZ);
                            memcpy(server.sendbuf, p_resp_msg,
                                         sizeof(ra_samp_response_header_t) + p_resp_msg->size);
                            DBG(OUTPUT, "\nSend attestation data\n");
                            PRINT_BYTE_ARRAY(OUTPUT, p_resp_msg, sizeof(ra_samp_response_header_t) + p_resp_msg->size);
                            int buflen = server.SendTo(sizeof(ra_samp_response_header_t) + p_resp_msg->size);
                            DBG(OUTPUT, "\nSend attestation data Done,send length = %d", buflen);
                        }

                        {
                            sample_ec_key_128bit_t secret;
                            get_secret(&secret);
                            put_secret_data(enclave_id,
                                            &status,
                                            secret);
                        }


                        SAFE_FREE(p_req);
                        SAFE_FREE(p_resp_msg);
                        break;
                    case TYPE_RA_KEYGEN:
                        DBG(OUTPUT, "\nProcess Keygen");
                        ret = pkg_keygen((const ra_samp_request_header_t *) ((uint8_t *) p_req +
                                                                             sizeof(ra_samp_request_header_t)),
                                         p_req->size,
                                         enclave_id,
                                         &status,
                                         aibeAlgo,
                                         server);
                        DBG(OUTPUT, "\nKeygen2 Done %d %d", enclave_id, status);
                        if (0 != ret) {
                            DBG(stderr, "\nError, call keygen fail [%s].",
                                    __FUNCTION__);
                        }
                        SAFE_FREE(p_req);
                        is_recv = false;
                        break;
                    case TYPE_RA_KEYREQ:
                        DBG(OUTPUT, "\nProcess Keyreq");
                        ret = pkg_keyreq((const uint8_t *) ((uint8_t *) p_req +
                                                                             sizeof(ra_samp_request_header_t)),
                                         p_req->size,
                                         enclave_id,
                                         &status,
                                         aibeAlgo,
                                         server);
                        DBG(OUTPUT, "\nKeyreq Done %d %d", enclave_id, status);
                        if (0 != ret) {
                            DBG(stderr, "\nError, call keyreq fail [%s].",
                                    __FUNCTION__);
                        }
                        SAFE_FREE(p_req);
                        is_recv = false;
                        break;

                    default:
                        ret = -1;
                        DBG(stderr, "\nError, unknown ra message type. Type = %d [%s].",
                                p_req->type, __FUNCTION__);
                        goto CLEANUP;
                }
            }
        } while (is_recv);

        ret = server.accept_client();
        if (ret) {
            DBG(OUTPUT, "\nAccept failed.");
            goto CLEANUP;
        }

    } while (true);


    puts("\npkg: keygen2 finished");

    CLEANUP:
    // Clean-up
    // Need to close the RA key state.
    if (INT_MAX != context) {
        int ret_save = ret;
        ret = enclave_ra_close(enclave_id, &status, context);
        if (SGX_SUCCESS != ret || status) {
            ret = -1;
            DBG(OUTPUT, "\nError, call enclave_ra_close fail [%s].",
                    __FUNCTION__);
        } else {
            // enclave_ra_close was successful, let's restore the value that
            // led us to this point in the code.
            ret = ret_save;
        }
        DBG(OUTPUT, "\nCall enclave_ra_close success.");
    }

    sgx_destroy_enclave(enclave_id);

    ra_free_network_response_buffer(p_msg0_resp_full);
    ra_free_network_response_buffer(p_msg2_full);
    ra_free_network_response_buffer(p_att_result_msg_full);

    server.Cleanupsocket();

    // p_msg3 is malloc'd by the untrusted KE library. App needs to free.
    SAFE_FREE(p_msg3);
    SAFE_FREE(p_msg3_full);
    SAFE_FREE(p_msg1_full);
    printf("\nExit ...\n");
    return ret;
}
