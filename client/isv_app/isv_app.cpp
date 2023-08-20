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
#include <ctime>
#include <stdio.h>
#include <unistd.h>
#include <json.hpp>
#include "ec_crypto.h"
#include <drogon/drogon.h>
#include "ra.h"
#include <chrono>


//#include "isv_enclave_u.h"


// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
#include "network_ra.h"

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
#include "log.h"

// 1--open   0--close
#define debug_enable (1)
#define DBG(...)      \
    if (debug_enable) \
    (fprintf(__VA_ARGS__))
#define ELE_DBG(...)  \
    if (debug_enable) \
    (element_fprintf(__VA_ARGS__))
#define _T(x) x

int experiment_enable(0);

using json = nlohmann::json;
using namespace std::chrono;
using namespace drogon;
typedef time_point<steady_clock> ts;

int loop = 10;
int pkg_port = 12333;
int lm_port = 22333;
std::string lm_ip = "121.41.111.120";
const std::string out_dir = "/root/experiments/PortexData/testing-data/";
//std::string lambda_file = out_dir + "lambda/lambda_" + std::to_string(qbits) + "_client.csv";
//std::string sn_file = out_dir + "N_SN/SN_" + std::to_string(N_SN) + "_client.csv";
std::string test_file = out_dir + "test_client.csv";
std::ofstream ofs_enc, ofs_dec, ofs_trace;

FILE *OUTPUT = stdout;
AibeAlgo aibeAlgo;
NetworkClient client;

// experiments vars
const int n_enc = 3, n_dec = 8, n_trace = 2;
std::vector<microseconds> ts_enc[n_enc], ts_dec[n_dec], ts_trace[n_trace];
ts s[n_dec], e[n_dec];

void getLocalTime(char *timeStr, int len, struct timeval tv);

int client_keyreq(NetworkClient networkClient, AibeAlgo &algo, FILE *output);

std::string client_encrypt(AibeAlgo &algo, int id, const std::string &message, bool enable_timer = true);

std::string client_decrypt(AibeAlgo &algo, const std::string &req_str, NetworkClient networkClient, bool enable_timer = true);

int client_trace(NetworkClient networkClient);

int client_inspect(int idsn, const std::string &dk2_path, AibeAlgo &algo);

void exp_enc();

void exp_dec();

void exp_trace();

void exp_tot();

int main(int argc, char *argv[]) {
    //    printf("%d\n", sizeof(uint8_t));
    int ret = 0;
//    sgx_enclave_id_t enclave_id = 0;

//    read args from command line, one integer for the number of loops
    if (argc > 1) {
        loop = atoi(argv[1]);
        experiment_enable = 1;
    }

    aibeAlgo.id = ID;
    aibeAlgo.sn = SN;
    // aibe load_param

    ////    aibe load_param
    if (aibeAlgo.load_param(param_path)) {
        DBG(stderr, "Param File Path error\n");
        exit(-1);
    }

    DBG(OUTPUT, "A-IBE Success Set Up\n");
    ////    element init
    aibeAlgo.init();

    // drogon add handler
    app().registerHandler(
            "/",
            [](const HttpRequestPtr &,
               std::function<void(const HttpResponsePtr &)> &&callback) {
                auto resp = HttpResponse::newHttpViewResponse("ClientView");
                callback(resp);
            });

    // drogon add encrypt handler, the parameter contains an integer id and a message. The response is a string that dumped from a json structure
    app().registerHandler("/encrypt?id={user-id}&message={message}", [&](const HttpRequestPtr &req,
                                                                         std::function<void(
                                                                                 const HttpResponsePtr &)> &&callback,
                                                                         const int &id,
                                                                         const std::string &message) {

        int ct_size;
        auto resp = HttpResponse::newHttpResponse();
        auto resp_str = client_encrypt(aibeAlgo, id, message);
        resp->setBody(resp_str);
        callback(resp);
    });


    // drogon add decrypt handler for POST, the request body contains a json structure with ct, sn, id, and the response is a string that contains the decrypted message
    app().registerHandler("/decrypt", [&](const HttpRequestPtr &req,
                                          std::function<void(const HttpResponsePtr &)> &&callback) {
        auto resp = HttpResponse::newHttpResponse();
        std::string req_str = req->body().data();
        std::string resp_str = client_decrypt(aibeAlgo, req_str, client);
        resp->setBody(resp_str);
        callback(resp);
    });


    if (!experiment_enable) {
        try {
            LOG_INFO << "Client running on 0.0.0.0:8080";
            drogon::app().loadConfigFile("./config.json");
            drogon::app().run();
        } catch (const std::exception &e) {
            LOG_ERROR << e.what();
        }
    } else {
//        exp_enc(); // experiment of Enc
//        exp_dec(); // experiment of KeyReq + Dec
//        exp_trace(); // experiment of Trace
        exp_tot();
    }


    CLEANUP:
    terminate(client);
    client.Cleanupsocket();
//    sgx_destroy_enclave(enclave_id);

    aibeAlgo.clear();
    DBG(OUTPUT, "Success Clean Up A-IBE \n");

    return ret;
}

void exp_tot() {
    {
        std::string enc_file = out_dir + "time-client-enc.csv";
        ofs_enc.open(enc_file);
        ofs_enc << "Portex.Enc(us)," // 0
                   "Enc.Setup(us)," // 1
                   "IBE.Enc(us)"
                << std::endl;

        std::string dec_file = out_dir + "time-client-dec.csv";
        ofs_dec.open(dec_file);
        ofs_dec << "KeyRequest(us)," // 0
                   "Portex.Dec(us)," // 1
                   "IBE.KGenC1," // 2
                   "KReq.SendReq," // 3
                   "KReq.Verify," // 4
                   "IBE.KGenC2," // 5
                   "Dec.Setup(us)," // 6
                   "IBE.Dec(us)" // 7
                << std::endl;

        std::string trace_file = out_dir + "time-client-trace.csv";
        ofs_trace.open(trace_file);
        ofs_trace << "Portex.DTrace(us)," // 0
                     "Portex.PTrace(us)" // 1
                  << std::endl;
    }

    std::string req_str;
    for (int i = 0; i < loop; ++i) {
        req_str = client_encrypt(aibeAlgo, ID, "Hello World!");
        client_decrypt(aibeAlgo, req_str, client);

        s[0] = steady_clock::now();
        client_trace(client);
        e[0] = steady_clock::now();
        s[1] = steady_clock::now();
        client_inspect(aibeAlgo.idsn(), dk_path, aibeAlgo);
        e[1] = steady_clock::now();

        if (experiment_enable) {
            for (int j = 0; j < n_trace; ++j) {
                ts_trace[j].emplace_back(duration_cast<microseconds>(e[j] - s[j]));
            }
        }

        ofs_enc << ts_enc[0][i].count() << ","
                << ts_enc[1][i].count() << ","
                << ts_enc[2][i].count() << std::endl;
        ofs_dec << ts_dec[0][i].count() << ","
                << ts_dec[1][i].count() << ","
                << ts_dec[2][i].count() << ","
                << ts_dec[3][i].count() << ","
                << ts_dec[4][i].count() << ","
                << ts_dec[5][i].count() << ","
                << ts_dec[6][i].count() << ","
                << ts_dec[7][i].count() << std::endl;
        ofs_trace << ts_trace[0][i].count() << ","
                  << ts_trace[1][i].count() << std::endl;

//        sleep for 1 milliseconds

//        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

//    for (int i = 0; i < loop; ++i) {
//    }
}

void exp_enc() {
    std::string enc_file = out_dir + "time-client-enc.csv";
    ofs_enc.open(enc_file);
    ofs_enc << "Portex.Enc(us)," // 0
               "Enc.Setup(us)," // 1
               "IBE.Enc(us)"
            << std::endl;

    ts_enc->clear();
    for (int i = 0; i < loop; ++i) {
        client_encrypt(aibeAlgo, ID, "Hello World!");
    }
    // output ts_enc to csv file
    for (int i = 0; i < loop; ++i) {
        ofs_enc << ts_enc[0][i].count() << ","
                << ts_enc[1][i].count() << ","
                << ts_enc[2][i].count() << std::endl;
    }
    ofs_enc.close();
}

void exp_dec() {

    std::string req_str = client_encrypt(aibeAlgo, ID, "Hello World!", false);
    std::string dec_file = out_dir + "time-client-dec.csv";
    ofs_dec.open(dec_file);
    ofs_dec << "KeyRequest(us)," // 0
               "Portex.Dec(us)," // 1
               "IBE.KGenC1," // 2
               "KReq.SendReq," // 3
               "KReq.Verify," // 4
               "IBE.KGenC2," // 5
               "Dec.Setup(us)," // 6
               "IBE.Dec(us)" // 7
            << std::endl;

    ts_dec->clear();
    for (int i = 0; i < loop; ++i) {
        client_decrypt(aibeAlgo, req_str, client);
    }
    // output ts_dec to csv file
    for (int i = 0; i < loop; ++i) {
        ofs_dec << ts_dec[0][i].count() << ","
                << ts_dec[1][i].count() << ","
                << ts_dec[2][i].count() << ","
                << ts_dec[3][i].count() << ","
                << ts_dec[4][i].count() << ","
                << ts_dec[5][i].count() << ","
                << ts_dec[6][i].count() << ","
                << ts_dec[7][i].count() << std::endl;
    }
}


void exp_trace() {
    std::string req_str = client_encrypt(aibeAlgo, ID, "Hello World!", false);
    client_decrypt(aibeAlgo, req_str, client, false);

    std::string trace_file = out_dir + "time-client-trace.csv";
    ofs_trace.open(trace_file);
    ofs_trace << "Portex.DTrace(us)," // 0
                 "Portex.PTrace(us)" // 1
              << std::endl;

    for (int i = 0; i < loop; ++i) {
        s[0] = steady_clock::now();
        client_trace(client);
        e[0] = steady_clock::now();
        s[1] = steady_clock::now();
        client_inspect(aibeAlgo.idsn(), dk_path, aibeAlgo);
        e[1] = steady_clock::now();

        if (experiment_enable) {
            for (int j = 0; j < n_trace; ++j) {
                ts_trace[j].emplace_back(duration_cast<microseconds>(e[j] - s[j]));
            }
        }
    }

    for (int i = 0; i < loop; ++i) {
        ofs_trace << ts_trace[0][i].count() << ","
                  << ts_trace[1][i].count() << std::endl;
    }
}

void getLocalTime(char *timeStr, int len, struct timeval tv) {
    struct tm *ptm;
    long milliseconds;

    ptm = localtime(&(tv.tv_sec));
    strftime(timeStr, len, "%Y-%m-%d %H-%M-%S", ptm);
    milliseconds = tv.tv_usec / 1000;

    sprintf(timeStr, "%s.%03ld", timeStr, milliseconds);
}

int client_keyreq(NetworkClient networkClient, AibeAlgo &algo, FILE *output) {

    int ret = 0;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int recvlen = 0;
    int busy_retry_time;
    int data_size;
    int msg_size;
    std::string msg_body;
    std::string sig, str_idsn;
    std::vector<uint8_t> vec_pms, vec_idsn, vec_sig, vec_pkey, vec_pkey_sig, vec_ct;

    json j_res;

    uint8_t p_data[LENOFMSE] = {0};

    // get idsn signature
    str_idsn = std::to_string(algo.idsn());
    vec_idsn = std::vector<uint8_t>(str_idsn.begin(), str_idsn.end());


    // get R and put into jason
    s[2] = steady_clock::now();
    algo.keygen1(algo.idsn());
    s[3] = e[2] = steady_clock::now();

    ecdsa_sign(vec_idsn, vec_sig, "param/client-sign.pem");

    data_size = algo.size_comp_G1 * 2;
    element_to_bytes_compressed(p_data, algo.R);
    element_to_bytes_compressed(p_data + algo.size_comp_G1, algo.Hz);
    vec_pms = std::vector<uint8_t>(p_data, p_data + data_size);

    e[3] = steady_clock::now();

    DBG(stdout, "\nData of R and Hz\n");
    PRINT_BYTE_ARRAY(stdout, p_data, data_size);

    ELE_DBG(output, "Send R:\n%B", algo.R);

    // construct json
    json json1 = {
            {"id",  algo.id},
            {"sn",  algo.sn},
            {"sig", vec_sig},
            {"pms", vec_pms}};
    msg_body = json1.dump();


    // construct request
    msg_size = msg_body.size() + 1;
    p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg_size);
    p_request->size = msg_size;
    p_request->type = TYPE_LM_KEYREQ;
    strcpy((char *) p_request->body, msg_body.c_str());

    puts((char *) p_request->body);

    // send request
    memset(networkClient.sendbuf, 0, BUFSIZ);
    memcpy(networkClient.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg_size);

    networkClient.SendTo(sizeof(ra_samp_request_header_t) + msg_size);
    // recv
    recvlen = networkClient.RecvFrom();
    p_response = (ra_samp_response_header_t *) malloc(
            sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) networkClient.recvbuf)->size);
    memcpy(p_response, networkClient.recvbuf, recvlen);

    if ((p_response->type != TYPE_LM_KEYREQ)) {
        DBG(stderr, "Error: INTERNAL ERROR - recv type error in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        printf("%d\n", p_response->type);
        ret = -1;
        goto CLEANUP;
    }

    if (p_response->status[1]) {
        DBG(stderr, "Error: LM ERROR - recv empty response in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        printf("%d\n", p_response->size);
        ret = -1;
        goto CLEANUP;
    }

    s[4] = steady_clock::now();

    j_res = json::parse(std::string((char *) p_response->body));
    j_res.at("pkey_ct").get_to(vec_ct);
    j_res.at("sig").get_to(vec_pkey_sig);

    ret = ecdsa_verify(vec_ct, vec_pkey_sig, "./param/pkg-verify.pem");

    if (ret) {
        std::cout << "pkey signature is valid" << std::endl;
    } else {
        std::cout << "ERR: pkey signature verify failed!" << std::endl;
        goto CLEANUP;
    }

    ecc_decrypt(vec_pkey, vec_ct, "param/client-sk.pem");
    // keygen 3

    dk_from_bytes(&algo.dk1, vec_pkey.data(), algo.size_comp_G1);
    {
        DBG(stdout, "Data of dk' is\n");
        ELE_DBG(stdout, "dk'.d1: %B\n", algo.dk1.d1);
        ELE_DBG(stdout, "dk'.d2: %B\n", algo.dk1.d2);
        ELE_DBG(stdout, "dk'.d3: %B\n", algo.dk1.d3);
    }
    e[4] = steady_clock::now();


    s[5] = steady_clock::now();
    if (algo.keygen3()) {
        DBG(stderr, "Error: INTERNAL ERROR - keygen3 error in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }
    e[5] = steady_clock::now();

    {
        DBG(stdout, "Data of dk is\n");
        ELE_DBG(stdout, "dk.d1: %B\n", algo.dk.d1);
        ELE_DBG(stdout, "dk.d2: %B\n", algo.dk.d2);
        ELE_DBG(stdout, "dk.d3: %B\n", algo.dk.d3);
    }
    algo.dk_store();

    CLEANUP:
    SAFE_FREE(p_response);
    return ret;
}

std::string client_encrypt(AibeAlgo &algo, int id, const std::string &message, bool enable_timer) {
//    clear s, e
    for (int i = 0; i < n_enc; ++i) {
        s[i] = e[i] = steady_clock::now();
    }

    s[0] = s[1] = steady_clock::now();

    int ct_size;
    std::string resp_str;
    uint8_t ct_buf[algo.size_ct + 10];

    algo.mpk_load();
    algo.id = id;
    algo.set_SN();

    e[1] = s[2] = steady_clock::now();

    ct_size = algo.encrypt(ct_buf, message.c_str(), algo.idsn());

    e[2] = steady_clock::now();

    std::vector ct = std::vector<uint8_t>(ct_buf, ct_buf + ct_size);
    json j = json{
            {"ct", ct},
            {"sn", algo.sn},
            {"id", algo.id}
    };

    std::ofstream(ct_path) << j;
    LOG_INFO << j.dump();
    resp_str += j.dump();

    e[0] = steady_clock::now();

    if (experiment_enable && enable_timer) {
        for (int i = 0; i < n_enc; ++i) {
            ts_enc[i].emplace_back(duration_cast<microseconds>(e[i] - s[i]));
        }
    }

    return resp_str;
}

std::string client_decrypt(AibeAlgo &algo, const std::string &req_str, NetworkClient networkClient, bool enable_timer) {

//    clear s, e
    for (int i = 0; i < n_enc; ++i) {
        s[i] = e[i] = steady_clock::now();
    }


    std::vector<uint8_t> ct;
    std::string resp_str;
//        LOG_INFO << req_str;
    json j = json::parse(req_str);
    j.at("ct").get_to(ct);
    uint8_t ct_buf[ct.size()];
    uint8_t msg_buf[algo.size_ct + 10];

    std::copy(ct.begin(), ct.end(), ct_buf);
    int ret = 0;

    close(networkClient.sockfd);
    if (networkClient.client(lm_ip.c_str(), lm_port) != 0) {
        resp_str = "Connect Server Error!";
        ret = -1;
    }

    s[0] = steady_clock::now();

    if (ret == 0) {
        algo.mpk_load();
        j.at("id").get_to(algo.id);
        j.at("sn").get_to(algo.sn);
        client_keyreq(networkClient, algo, OUTPUT);

        s[6] = s[1] = e[0] = steady_clock::now();

        LOG_INFO << "Start Decrypt";
        LOG_INFO << "json" << j.dump();

        algo.dk_load();
        int ct_size = ct.size();

        std::copy(ct.begin(), ct.end(), ct_buf);

        s[7] = e[6] = steady_clock::now();

        algo.decrypt(msg_buf, ct_buf, ct_size);

        e[7] = steady_clock::now();
        LOG_INFO << "Decrypted Message:\n" << msg_buf;
        resp_str = std::string((char *) msg_buf);
    }

    e[1] = steady_clock::now();

    if (experiment_enable && enable_timer) {
        for (int i = 0; i < n_dec; ++i) {
            ts_dec[i].emplace_back(duration_cast<microseconds>(e[i] - s[i]));
        }
    }

    return resp_str;
}

int client_trace(NetworkClient networkClient) {

    std::string str;
    int ret = 0;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int recvlen = 0;
    int busy_retry_time;
    int data_size;
    int msg_size;
    int n;
    timeval *tv_list;
    char timeStr[128];
    json j, j_node;
    Proofs proofs;
    std::vector<uint8_t> vec_prf;
    uint8_t data[BUFSIZ];

    close(networkClient.sockfd);
    if (networkClient.client(lm_ip.c_str(), lm_port) != 0) {
        LOG_INFO << "Connect Server Error!";
        ret = -1;
    }

    s[0] = steady_clock::now();

    msg_size = sizeof(int);
    p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg_size);
    p_request->size = msg_size;
    p_request->type = TYPE_LM_TRACE;
    *((int *) p_request->body) = aibeAlgo.idsn();
    LOG_INFO << "ID: " << aibeAlgo.id << " SN: " << aibeAlgo.sn << " IDSN: " << aibeAlgo.idsn();

    memset(networkClient.sendbuf, 0, BUFSIZ);
    memcpy(networkClient.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg_size);
    int status = networkClient.SendTo(sizeof(ra_samp_request_header_t) + msg_size);
    if (status < 0) {
        DBG(stderr, "Error, sendto error[%s]-[%d].\n", __FUNCTION__, __LINE__);
        LOG_INFO << status;
        ret = -1;
        goto CLEANUP;
    }

    // recv
    recvlen = networkClient.RecvFrom();
    if (recvlen < 0) {
        DBG(stderr, "Error, recvfrom error[%s]-[%d].\n", __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }

    p_response = (ra_samp_response_header_t *) malloc(
            sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) networkClient.recvbuf)->size);

    LOG_INFO << "Recvlen: " << recvlen << "; size: " << p_response->size;

    memcpy(p_response, networkClient.recvbuf, recvlen);
    if ((p_response->type != TYPE_LM_TRACE)) {
        DBG(stderr, "Error: INTERNAL ERROR - recv type error in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        printf("%d\n", p_response->type);
        ret = -1;
        goto CLEANUP;
    }

    if (p_response->size <= 1) {
        // log not found
        LOG_INFO << "Log not found";
        ret = -1;
        goto CLEANUP;
    }

    LOG_INFO << "Log node received";

    str = std::string((char *) p_response->body);
    LOG_INFO << "\nReceive Log json. Size: " << p_response->size << "; recv size: " << recvlen;
    j = json::parse(str);
    j_node = j.at("node");
    j.at("prf").get_to(vec_prf);
    // vec_prf -> data
    data_size = vec_prf.size();
    std::copy(vec_prf.begin(), vec_prf.end(), data);

    proofs.deserialise(data);

    if (!proofs.verify_proofs()) {
        printf("Proofs is invalid!\n");
        ret = -1;
        goto CLEANUP;
    }

    LOG_INFO << "Proofs is valid!";
    LOG_INFO << "node: " << j_node.dump();

    CLEANUP:
    SAFE_FREE(p_request);
    SAFE_FREE(p_response);
    return ret;
}

int client_inspect(int idsn, const std::string &dk2_path, AibeAlgo &algo) {
    algo.dk_load();
    algo.dk2_load(dk2_path);
    algo.mpk_load();
    algo.set_Hz(idsn);

    if (!algo.dk_verify()) {
        printf("Client decrypt key is invalid!\n");
        return -1;
    }
    printf("Client decrypt key is valid!\n");

    if (!algo.dk_verify(algo.dk2)) {
        printf("Input decrypt key is invalid!\n");
        return 0;
    }
    printf("Input decrypt key is valid!\n");

    if (element_cmp(algo.dk.d1, algo.dk2.d1) || element_cmp(algo.dk.d2, algo.dk2.d2) ||
        element_cmp(algo.dk.d3, algo.dk2.d3)) {
        printf("Another valid key detected!\n");
        return 1;
    }

    printf("The same key detected!\n");
    return 0;
}


