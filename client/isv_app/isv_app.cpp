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

#include <iostream>
#include <fstream>
#include <ctime>
#include "ra.h"
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <json.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/oids.h>
#include <cryptopp/pem.h>
#include "cryptopp/files.h"

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

//1--open   0--close
#define test_enable (1)
#define debug_enable (1)
#define DBG(...) if(debug_enable)(fprintf(__VA_ARGS__))
#define ELE_DBG(...) if(debug_enable)(element_fprintf(__VA_ARGS__))
#define _T(x) x

using json = nlohmann::json;
using namespace CryptoPP;

FILE *OUTPUT = stdout;

void getLocalTime(char *timeStr, int len, struct timeval tv) {
    struct tm *ptm;
    long milliseconds;

    ptm = localtime(&(tv.tv_sec));
    strftime(timeStr, len, "%Y-%m-%d %H-%M-%S", ptm);
    milliseconds = tv.tv_usec / 1000;

    sprintf(timeStr, "%s.%03ld", timeStr, milliseconds);
}

std::string get_sig(std::string message) {
    AutoSeededRandomPool prng;
    ECDSA<ECP, SHA256>::PrivateKey sk;
    FileSource fs_pri("param/ec-pri.pem", true);
    PEM_Load(fs_pri, sk);
    ECDSA<ECP, SHA256>::Signer signer(sk);

    size_t siglen = signer.MaxSignatureLength();
    std::string sig(siglen, 0x00);
    siglen = signer.SignMessage(prng, (const byte *) &message[0], message.size(), (byte *) &sig[0]);
    sig.resize(siglen);

    return sig;
}

int client_keyreq(NetworkClient client, AibeAlgo &aibeAlgo, sgx_enclave_id_t enclave_id, FILE *OUTPUT, double &time) {

    int ret = 0;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int recvlen = 0;
    int busy_retry_time;
    int data_size;
    int msg_size;
    std::string msg_body;
    std::string sig, str_idsn;
    std::vector<uint8_t> vec_pms, vec_sig, vec_pkey;

//    test
    clock_t st, et;
    json j_res;

    uint8_t p_data[LENOFMSE] = {0};

    // get idsn signature
    str_idsn = std::to_string(aibeAlgo.idsn());
    sig = get_sig(str_idsn);
    vec_sig = std::vector<uint8_t>(sig.c_str(), sig.c_str() + sig.size());

    // get R and put into jason
    aibeAlgo.keygen1(aibeAlgo.idsn());

    data_size = aibeAlgo.size_comp_G1 * 2;
    element_to_bytes_compressed(p_data, aibeAlgo.R);
    element_to_bytes_compressed(p_data + aibeAlgo.size_comp_G1, aibeAlgo.Hz);
    vec_pms = std::vector<uint8_t>(p_data, p_data + data_size);

    DBG(stdout, "\nData of R and Hz\n");
    PRINT_BYTE_ARRAY(stdout, p_data, data_size);

    ELE_DBG(OUTPUT, "Send R:\n%B", aibeAlgo.R);

    // construct json
    json json1 = {
            {"id",  aibeAlgo.id},
            {"sn",  aibeAlgo.sn},
            {"sig", vec_sig},
            {"pms", vec_pms}
    };
    msg_body = json1.dump();

    // construct request
    msg_size = msg_body.size() + 1;
    p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg_size);
    p_request->size = msg_size;
    p_request->type = TYPE_LM_KEYREQ;
    strcpy((char *) p_request->body, msg_body.c_str());

    puts((char *) p_request->body);

    // send request
    memset(client.sendbuf, 0, BUFSIZ);
    memcpy(client.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg_size);
    client.SendTo(sizeof(ra_samp_request_header_t) + msg_size);

    // recv
    recvlen = client.RecvFrom();
    p_response = (ra_samp_response_header_t *) malloc(
            sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) client.recvbuf)->size);

    et = clock();
    time = et - st;

    memcpy(p_response, client.recvbuf, recvlen);
    if ((p_response->type != TYPE_LM_KEYREQ)) {
        DBG(stderr, "Error: INTERNAL ERROR - recv type error in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        printf("%d\n", p_response->type);
        ret = -1;
        goto CLEANUP;
    }

    j_res = json::parse(std::string((char *)p_response->body));
    j_res.at("pkey").get_to(vec_pkey);

    std::copy(vec_pkey.begin(), vec_pkey.end(), p_data);

    // keygen 3

    dk_from_bytes(&aibeAlgo.dk1, p_data, aibeAlgo.size_comp_G1);
    {
        DBG(stdout, "Data of dk' is\n");
        ELE_DBG(stdout, "dk'.d1: %B\n", aibeAlgo.dk1.d1);
        ELE_DBG(stdout, "dk'.d2: %B\n", aibeAlgo.dk1.d2);
        ELE_DBG(stdout, "dk'.d3: %B\n", aibeAlgo.dk1.d3);
    }

    if (aibeAlgo.keygen3()) {
        ret = -1;
        goto CLEANUP;
    }

    {
        DBG(stdout, "Data of dk is\n");
        ELE_DBG(stdout, "dk.d1: %B\n", aibeAlgo.dk.d1);
        ELE_DBG(stdout, "dk.d2: %B\n", aibeAlgo.dk.d2);
        ELE_DBG(stdout, "dk.d3: %B\n", aibeAlgo.dk.d3);
    }
    aibeAlgo.dk_store();

    CLEANUP:
    SAFE_FREE(p_response);
    return ret;
}


int client_keygen(int id, AibeAlgo &aibeAlgo, sgx_enclave_id_t enclave_id, FILE *OUTPUT, NetworkClient client,
                  double &time) {
    int ret = 0;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int recvlen = 0;
    int busy_retry_time;
    int data_size;
    int msg_size;

//    test
    clock_t st, et;

    uint8_t p_data[LENOFMSE] = {0};
    uint8_t p2_data[LENOFMSE] = {0};
    uint8_t out_data[LENOFMSE] = {0};
    sgx_aes_gcm_128bit_tag_t mac;

    // keygen 1
    aibeAlgo.keygen1(id);

    data_size = aibeAlgo.size_comp_G1 * 2;
    element_to_bytes_compressed(p_data, aibeAlgo.R);
    element_to_bytes_compressed(p_data + aibeAlgo.size_comp_G1, aibeAlgo.Hz);
    ra_encrypt(p_data, data_size, out_data, mac, enclave_id, OUTPUT);
    DBG(stdout, "\nData of Encrypted R and its MAC is\n");
    PRINT_BYTE_ARRAY(stdout, out_data, data_size);
    PRINT_BYTE_ARRAY(stdout, mac, SGX_AESGCM_MAC_SIZE);

    ELE_DBG(OUTPUT, "Send R:\n%B", aibeAlgo.R);

    msg_size = data_size + SGX_AESGCM_MAC_SIZE;
    p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg_size);
    p_request->size = msg_size;
    p_request->type = TYPE_RA_KEYGEN;

    memcpy(p_request->body, out_data, data_size);
    memcpy(p_request->body + data_size, mac, SGX_AESGCM_MAC_SIZE);

//    PKG communication time
    st = clock();
    memset(client.sendbuf, 0, BUFSIZ);
    memcpy(client.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg_size);
    client.SendTo(sizeof(ra_samp_request_header_t) + p_request->size);

    // keygen 3
    recvlen = client.RecvFrom();
    p_response = (ra_samp_response_header_t *) malloc(
            sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) client.recvbuf)->size);

    et = clock();
    time = et - st;

    memcpy(p_response, client.recvbuf, recvlen);
    if ((p_response->type != TYPE_RA_KEYGEN)) {
        DBG(OUTPUT, "Error: INTERNAL ERROR - return type mismatch in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }

    data_size = p_response->size - SGX_AESGCM_MAC_SIZE;

    memcpy(p_data, p_response->body, data_size);
    memcpy(mac, p_response->body + data_size, SGX_AESGCM_MAC_SIZE);
//    DBG(OUTPUT, "Success Encrypt\n");
//    PRINT_BYTE_ARRAY(OUTPUT, p_data, sizeof(p_data));
//    DBG(OUTPUT, "Encrypt Mac\n");
//    PRINT_BYTE_ARRAY(OUTPUT, mac, SGX_AESGCM_MAC_SIZE);

    ra_decrypt(p_data, data_size, out_data, mac, enclave_id, OUTPUT);

    dk_from_bytes(&aibeAlgo.dk1, out_data, aibeAlgo.size_comp_G1);
    {
        DBG(stdout, "Data of dk' is\n");
        ELE_DBG(stdout, "dk'.d1: %B\n", aibeAlgo.dk1.d1);
        ELE_DBG(stdout, "dk'.d2: %B\n", aibeAlgo.dk1.d2);
        ELE_DBG(stdout, "dk'.d3: %B\n", aibeAlgo.dk1.d3);
    }

    if (aibeAlgo.keygen3()) {
        ret = -1;
        goto CLEANUP;
    }

    {
        DBG(stdout, "Data of dk is\n");
        ELE_DBG(stdout, "dk.d1: %B\n", aibeAlgo.dk.d1);
        ELE_DBG(stdout, "dk.d2: %B\n", aibeAlgo.dk.d2);
        ELE_DBG(stdout, "dk.d3: %B\n", aibeAlgo.dk.d3);
    }

    CLEANUP:
    SAFE_FREE(p_response);
    return ret;
}


// todo: change to json
int client_trace(NetworkClient client) {

    int ret = 0;
    sgx_status_t status = SGX_SUCCESS;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int recvlen = 0;
    int busy_retry_time;
    int data_size;
    int msg_size;
    int n;
    timeval *tv_list;
    char timeStr[128];

    msg_size = sizeof(int);
    p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg_size);
    p_request->size = msg_size;
    p_request->type = TYPE_LM_TRACE;
    *((int *) p_request->body) = IDSN;

    memset(client.sendbuf, 0, BUFSIZ);
    memcpy(client.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg_size);
    client.SendTo(sizeof(ra_samp_request_header_t) + msg_size);

// recv
    recvlen = client.RecvFrom();
    p_response = (ra_samp_response_header_t *) malloc(
            sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) client.recvbuf)->size);

    memcpy(p_response, client.recvbuf, recvlen);
    if ((p_response->type != TYPE_LM_TRACE)) {
        DBG(stderr, "Error: INTERNAL ERROR - recv type error in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        printf("%d\n", p_response->type);
        ret = -1;
        goto CLEANUP;
    }
    DBG(OUTPUT, "Log list received");

    n = p_response->size / sizeof(timeval);
    tv_list = (timeval *) p_response->body;

    fprintf(OUTPUT, "\nID: %d\n", IDSN);
    for (int i = 0; i < n; ++i) {
        getLocalTime(timeStr, sizeof(timeStr), tv_list[i]);
        printf("<%d>: %s\n", i, timeStr);
    }

    CLEANUP:
    SAFE_FREE(p_request);
    SAFE_FREE(p_response);
    return ret;
}

int client_inspect(const std::string &dk2_path, AibeAlgo &aibeAlgo) {
    aibeAlgo.dk_load();
    aibeAlgo.dk2_load(dk2_path);
    aibeAlgo.mpk_load();
    aibeAlgo.set_Hz(IDSN);

    if (!aibeAlgo.dk_verify()) {
        printf("Client decrypt key is invalid!\n");
        return -1;
    }
    printf("Client decrypt key is valid!\n");

    if (!aibeAlgo.dk_verify(aibeAlgo.dk2)) {
        printf("Input decrypt key is invalid!\n");
        return 0;
    }
    printf("Input decrypt key is valid!\n");

    if (element_cmp(aibeAlgo.dk.d1, aibeAlgo.dk2.d1)
        || element_cmp(aibeAlgo.dk.d2, aibeAlgo.dk2.d2)
        || element_cmp(aibeAlgo.dk.d3, aibeAlgo.dk2.d3)) {
        printf("Another valid key detected!\n");
        return 1;
    }

    printf("The same key detected!\n");
    return 0;
}

int main(int argc, char *argv[]) {
//    printf("%d\n", sizeof(uint8_t));
    int ret = 0;
    sgx_enclave_id_t enclave_id = 0;
    AibeAlgo aibeAlgo;
    NetworkClient client;
    int pkg_port = 12333;
    int lm_port = 22333;
    int mod = 0;
    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    FILE *f;
    int ct_size, msg_size;
    std::string dk2_path;


    // test

    sgx_status_t status = SGX_SUCCESS;
    int busy_retry_time;
    int data_len = 1 << 13;
    uint8_t data[data_len];
    uint8_t output[data_len];
    uint8_t mac[data_len];
    sgx_ec256_public_t ecc_pub;
    sgx_ec256_private_t ecc_pri;
    sgx_ec256_signature_t ecc_sig;
    sgx_ecc_state_handle_t ecc_handle;
    uint8_t result;

//    test vars
    int loops = 1;
    clock_t cnt;
    clock_t start, end;
    double sum, sum_pkg, ra_temp;
    double ts[10100], ts_pkg[10100];
    json j;

    aibeAlgo.id = ID;
    aibeAlgo.sn = SN;
    //aibe load_param

////    aibe load_param
    if (aibeAlgo.load_param(param_path)) {
        DBG(stderr, "Param File Path error\n");
        exit(-1);
    }
//    printf("%d, %d, %d\n", aibeAlgo.size_GT, aibeAlgo.size_comp_G1, aibeAlgo.size_Zr);
    uint8_t ct_buf[aibeAlgo.size_ct + 10];
    uint8_t msg_buf[aibeAlgo.size_ct + 10];
    std::vector<uint8_t> ct;
    std::vector<uint8_t> msg;
    DBG(OUTPUT, "A-IBE Success Set Up\n");
////    element init
    aibeAlgo.init();

    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
    {
        ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                                 SGX_DEBUG_FLAG,
                                 &launch_token,
                                 &launch_token_update,
                                 &enclave_id, NULL);
        if (SGX_SUCCESS != ret) {
            ret = -1;
            DBG(OUTPUT, "Error, call sgx_create_enclave fail [%s].\n",
                __FUNCTION__);
            goto CLEANUP;
        }
        DBG(OUTPUT, "Call sgx_create_enclave success.\n");
    }

//    aibeAlgo.load_param(param_path);
//    aibeAlgo.init();
//    aibeAlgo.dk_load();
//    aibeAlgo.mpk_load();
//    element_random(aibeAlgo.m);
//    element_printf("%B\n", aibeAlgo.m);
//    aibeAlgo.block_encrypt(idsn);
//    aibeAlgo.ct_write();
//    aibeAlgo.ct_read();
//    aibeAlgo.block_decrypt();
//    element_printf("%B\n", aibeAlgo.m);

    for (int i = 0; i < data_len; ++i) {
        data[i] = i / 10;
    }
    printf("Please choose a function:\n"
           "1) encrypt\n"
           "2) key request\n"
           "20) key generation\n"
           "3) decrypt\n"
           "4) log trace\n"
           "5) tee inspect\n"
           "Please input a number:");
    scanf("%d", &mod);


    switch (mod) {
        case 0: {
            std::cout << "Generated client (vk, sk)" << std::endl;

            std::string str_idsn = std::to_string(aibeAlgo.idsn());
            AutoSeededRandomPool prng;
            ECDSA<ECP, SHA256>::PrivateKey sk;
            sk.Initialize(prng, ASN1::secp256r1());
            ECDSA<ECP, SHA256>::Signer signer(sk);


            ECDSA<ECP, SHA256>::PublicKey pk;
            sk.MakePublicKey(pk);


            FileSink fs_pri("param/ec-pri.pem", true);
            PEM_Save(fs_pri, sk);

            FileSink fs_pub("param/ec-pub.pem", true);
            PEM_Save(fs_pub, pk);

        }
            break;

        case 1:
            // Encrypt
            aibeAlgo.mpk_load();
            DBG(OUTPUT, "Client: setup finished");
            DBG(OUTPUT, "Start Encrypt\n");
            std::cout << "Receiver ID: " << std::endl;
//            std::cin >> id;

            f = fopen(msg_path, "r+");
            msg_size = fread(msg_buf, sizeof(uint8_t), aibeAlgo.size_ct, f);
            fclose(f);

            fprintf(OUTPUT, "Message:\n%s\n", msg_buf);
            DBG(OUTPUT, "Message size: %d\n", msg_size);

            ct_size = aibeAlgo.encrypt(ct_buf, (char *) msg_buf, aibeAlgo.idsn());

            ct = std::vector<uint8_t>(ct_buf, ct_buf + ct_size);
            j = json{
                    {"id", ID},
                    {"sn", SN},
                    {"ct", ct}
            };

            std::ofstream(ct_path) << j;

            DBG(OUTPUT, "encrypt size: %d, block size %d\n", ct_size, aibeAlgo.size_block);

            break;

        case 2:

            sum = sum_pkg = 0;
            aibeAlgo.mpk_load();
            for (int i = 0; i < loops; ++i) {
                start = clock();

                if (client.client("127.0.0.1", lm_port) != 0) {
                    DBG(OUTPUT, "Connect Server Error, Exit!\n");
                    ret = -1;
                    goto CLEANUP;
                }
                client_keyreq(client, aibeAlgo, enclave_id, OUTPUT, ts_pkg[i]);
                DBG(OUTPUT, "Key request finished\n");
//                ts_pkg[i] += ra_temp;
                end = clock();
                ts[i] = end - start;
                sum += ts[i];
//                sum_pkg += ts_pkg[i];
            }

//            printf("%d,%lf\n", N, sum / loops);
            break;

        case 20:
// KGen
            sum = sum_pkg = 0;
            aibeAlgo.mpk_load();
            for (int i = 0; i < loops; ++i) {
                start = clock();
                if (client.client("127.0.0.1", pkg_port) != 0) {
                    DBG(OUTPUT, "Connect Server Error, Exit!\n");
                    ret = -1;
                    goto CLEANUP;
                }

                DBG(OUTPUT, "Start key generation\n");
                // SOCKET: connect to server
                ra_temp = clock();

                if (remote_attestation(enclave_id, client) != SGX_SUCCESS) {
                    DBG(OUTPUT, "Remote Attestation Error, Exit!\n");
                    ret = -1;
                    goto CLEANUP;
                }
                ra_temp = clock() - ra_temp;

                DBG(OUTPUT, "Client: setup finished");
////    aibe: keygen
                if (client_keygen(aibeAlgo.idsn(), aibeAlgo, enclave_id, OUTPUT, client, ts_pkg[i])) {
                    DBG(stderr, "Key verify failed\n");
                    goto CLEANUP;
                }
                aibeAlgo.dk_store();
                DBG(OUTPUT, "A-IBE Success Keygen \n");

                ts_pkg[i] += ra_temp;
                end = clock();
                ts[i] = end - start;
                sum += ts[i];
                sum_pkg += ts_pkg[i];
            }

//            printf("%d,%lf,%lf\n", N, sum / loops, sum_pkg / loops);
            break;

        case 3:
            aibeAlgo.dk_load();
            aibeAlgo.mpk_load();
            DBG(OUTPUT, "Client: setup finished\n");
            DBG(OUTPUT, "Start Decrypt\n");

            std::ifstream(ct_path) >> j;
            j.at("ct").get_to(ct);
            j.at("id").get_to(aibeAlgo.id);
            j.at("sn").get_to(aibeAlgo.sn);
            ct_size = ct.size();

            DBG(OUTPUT, "decrypt size: %d, ct size: %zu\n", ct_size, ct.size());

            std::copy(ct.begin(), ct.end(), ct_buf);

            aibeAlgo.decrypt(msg_buf, ct_buf, ct_size);
            printf("%s\n", msg_buf);

            f = fopen(out_path, "w+");
            fwrite(msg_buf, strlen((char *) msg_buf), 1, f);
            fclose(f);

            break;

        case 4:

            if (client.client("127.0.0.1", lm_port) != 0) {
                DBG(OUTPUT, "Connect Server Error, Exit!\n");
                ret = -1;
                goto CLEANUP;
            }
            client_trace(client);
            DBG(OUTPUT, "Log trace finished\n");

            break;


        case 5:

            printf("Please input decrypt key file path:\n");
            std::cin >> dk2_path;
            ret = client_inspect(dk2_path, aibeAlgo);
            DBG(OUTPUT, "[DBG] TEE inspect finished\n");

            {
                DBG(stdout, "[DBG] Client decrypt key:\n");
                ELE_DBG(stdout, "dk.d1: %B\n", aibeAlgo.dk.d1);
                ELE_DBG(stdout, "dk.d2: %B\n", aibeAlgo.dk.d2);
                ELE_DBG(stdout, "dk.d3: %B\n", aibeAlgo.dk.d3);
            }

            {
                DBG(stdout, "[DBG] Input decrypt key:\n");
                ELE_DBG(stdout, "dk2.d1: %B\n", aibeAlgo.dk2.d1);
                ELE_DBG(stdout, "dk2.d2: %B\n", aibeAlgo.dk2.d2);
                ELE_DBG(stdout, "dk2.d3: %B\n", aibeAlgo.dk2.d3);
            }

            switch (ret) {
                case 0:
                    printf("PASS: No misbehavior detected!\n");
                    break;
                case -1:
                    printf("ERROR: TEE inspect failed\n");
                    break;
                case 1:
                    printf("FAILED: TEE misbehavior detected!\n");
                    break;
                default:
                    DBG(OUTPUT, "ERROR: TEE inspect failed\n");
            }

            break;

        case 101:
//            test of RA
            DBG(OUTPUT, "Start key generation\n");
            // SOCKET: connect to server
            if (client.client("127.0.0.1", pkg_port) != 0) {
                DBG(OUTPUT, "Connect Server Error, Exit!\n");
                ret = -1;
                goto CLEANUP;
            }


            sum = 0;
            for (int i = 0; i < 100; ++i) {
                start = clock();
                if (remote_attestation(enclave_id, client) != SGX_SUCCESS) {
                    DBG(OUTPUT, "Remote Attestation Error, Exit!\n");
                    ret = -1;
                    goto CLEANUP;
                }
                end = clock();
                ts[i] = end - start;
                sum += ts[i];
            }
            printf("ra time(ms): %lf\n", double(sum) / CLOCKS_PER_SEC * 10);
            for (int i = 0; i < 100; ++i) {
                printf("%ld\n", ts[i]);
            }
            aibeAlgo.mpk_load();
            DBG(OUTPUT, "Client: setup finished");
////    aibe: keygen
            if (client_keygen(aibeAlgo.idsn(), aibeAlgo, enclave_id, OUTPUT, client, sum_pkg)) {
                DBG(stderr, "Key verify failed\n");
                goto CLEANUP;
            }
            aibeAlgo.dk_store();
            DBG(OUTPUT, "A-IBE Success Keygen \n");

            break;
        case 102:
//            test of aes

            enclave_use(enclave_id);
            sum = 0;
            for (int i = 0; i < 100; ++i) {
                busy_retry_time = 4;
                start = clock();
                do {
                    ret = enclave_encrypt(
                            enclave_id,
                            &status,
                            data,
                            data_len,
                            output,
                            mac);
                } while (SGX_ERROR_BUSY == ret && busy_retry_time--);

                if (ret != SGX_SUCCESS) {
                    DBG(OUTPUT, "102 error");
                    goto CLEANUP;
                }

                end = clock();
                ts[i] = end - start;
                sum += ts[i];
            }
            printf("SE Encrypt Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }

            sum = 0;
            for (int i = 0; i < 100; ++i) {
                busy_retry_time = 4;
                start = clock();
                do {
                    ret = enclave_encrypt(
                            enclave_id,
                            &status,
                            output,
                            data_len,
                            data,
                            mac);
                } while (SGX_ERROR_BUSY == ret && busy_retry_time--);


                if (ret != SGX_SUCCESS) {
                    DBG(OUTPUT, "102 error");
                    goto CLEANUP;
                }

                end = clock();
                ts[i] = end - start;
                sum += ts[i];
            }
            printf("SE Decrypt Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }
            break;


        case 103:
            enclave_use(enclave_id);

            sum = 0;
            for (int i = 0; i < 100; ++i) {
                start = clock();

                ret = enclave_ecc_init(enclave_id,
                                       &status,
                                       &ecc_pri,
                                       &ecc_pub,
                                       &ecc_handle);

                if (ret != SGX_SUCCESS && status != SGX_SUCCESS) {
                    DBG(OUTPUT, "103 error");
                    goto CLEANUP;
                }
                end = clock();
                ts[i] = end - start;
                sum += ts[i];
            }
            printf("ECDSA Kgen Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }

            sum = 0;
            for (int i = 0; i < 100; ++i) {
                start = clock();

                ret = enclave_ecc_sign(enclave_id,
                                       &status,
                                       data,
                                       data_len,
                                       &ecc_pri,
                                       &ecc_sig,
                                       (uint8_t *) &ecc_handle);

                if (ret != SGX_SUCCESS) {
                    DBG(OUTPUT, "103 error");
                    goto CLEANUP;
                }
                end = clock();
                ts[i] = end - start;
                sum += ts[i];
            }
            printf("ECDSA Sign Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }

            sum = 0;
            for (int i = 0; i < 100; ++i) {
                start = clock();

                ret = enclave_ecc_verify(enclave_id,
                                         &status,
                                         data,
                                         data_len,
                                         &ecc_pub,
                                         &ecc_sig,
                                         &result,
                                         (uint8_t *) &ecc_handle);

                if (ret != SGX_SUCCESS) {
                    DBG(OUTPUT, "103 error");
                    goto CLEANUP;
                }

                end = clock();
                ts[i] = end - start;
                sum += ts[i];
            }
            printf("ECDSA Verify Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }

            break;

        case 104:

            enclave_ecc_init(enclave_id,
                             &status,
                             &ecc_pri,
                             &ecc_pub,
                             &ecc_handle);

            sum = 0;

            enclave_use(enclave_id);


            for (int i = 0; i < 100; ++i) {
                start = clock();

                enclave_ecc_init(enclave_id,
                                 &status,
                                 &ecc_pri,
                                 &ecc_pub,
                                 &ecc_handle);


                end = clock();
                ts[i] = double(end - start);
                sum += ts[i];
            }
            printf("ECC KGen Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }

            for (int i = 0; i < 100; ++i) {
                start = clock();

                ret = enclave_ecc_sign(enclave_id,
                                       &status,
                                       data,
                                       data_len,
                                       &ecc_pri,
                                       &ecc_sig,
                                       (uint8_t *) &ecc_handle);

                if (ret != SGX_SUCCESS) {
                    DBG(OUTPUT, "104 error");
                    goto CLEANUP;
                }
                end = clock();
                ts[i] = double(end - start);
                sum += ts[i];
            }
            printf("ECC Decrypt Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }

            sum = 0;
            for (int i = 0; i < 100; ++i) {
                start = clock();

                ret = enclave_ecc_verify(enclave_id,
                                         &status,
                                         data,
                                         data_len,
                                         &ecc_pub,
                                         &ecc_sig,
                                         &result,
                                         (uint8_t *) &ecc_handle);

                if (ret != SGX_SUCCESS) {
                    DBG(OUTPUT, "104 error");
                    goto CLEANUP;
                }

                end = clock();
                ts[i] = double(end - start);
                sum += ts[i];
            }
            printf("ECC Encrypt Time(μs): %lf\n", double(sum) / 100);
            for (int i = 0; i < 100; ++i) {
                printf("%d\n", (int) ts[i]);
            }

            break;
        default:
            printf("Invalid function number, exit\n");
            goto CLEANUP;
    }


    CLEANUP:
    terminate(client);
    client.Cleanupsocket();
    sgx_destroy_enclave(enclave_id);

    aibeAlgo.clear();
    DBG(OUTPUT, "Success Clean Up A-IBE \n");

    return ret;
}
