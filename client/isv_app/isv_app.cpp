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
bool lock = false;

int loop = 10;
int pkg_port = 12333;
int lm_port = 22333;

std::string lm_ip = "47.121.124.25";

const std::string out_dir = "/root/experiments/PortexData/testing-data/";
//std::string lambda_file = out_dir + "lambda/lambda_" + std::to_string(qbits) + "_client.csv";
//std::string sn_file = out_dir + "N_SN/SN_" + std::to_string(N_SN) + "_client.csv";
std::string test_file = out_dir + "test_client.csv";
std::ofstream ofs_enc, ofs_dec, ofs_trace;

FILE *OUTPUT = stdout;

// experiments vars
const int n_enc = 3, n_dec = 8, n_trace = 2;
std::vector<microseconds> ts_enc[n_enc], ts_dec[n_dec], ts_trace[n_trace];
ts s[n_dec], e[n_dec];

void getLocalTime(char *timeStr, int len, struct timeval tv);

int client_keyreq(NetworkClient &client, AibeAlgo &algo, json &j_header, std::vector<uint8_t> &vec_quote, FILE *output);

std::string client_encrypt(NetworkClient client, AibeAlgo &algo, int id, int sec, const std::string &message, bool enable_timer = true);

std::string client_decrypt(NetworkClient client, AibeAlgo &algo, const std::string &req_str, bool enable_timer = true);

int client_trace(NetworkClient client, AibeAlgo &aibeAlgo);

int client_inspect(int idsn, const std::string &dk2_path, AibeAlgo &algo);

void exp_enc(NetworkClient client, AibeAlgo &aibeAlgo);

void exp_dec(NetworkClient client, AibeAlgo &aibeAlgo);

void exp_trace(NetworkClient client, AibeAlgo &aibeAlgo);

void exp_tot(NetworkClient client);

int main(int argc, char *argv[]) {
    //    printf("%d\n", sizeof(uint8_t));
    int ret = 0;
//    sgx_enclave_id_t enclave_id = 0;

//    read args from command line, one integer for the number of loops
    if (argc > 1) {
        loop = atoi(argv[1]);
        experiment_enable = 1;
    }

    NetworkClient client;
    // aibe load_param


    // drogon add handler
//    app().registerHandler(
//            "/",
//            [](const HttpRequestPtr &,
//               std::function<void(const HttpResponsePtr &)> &&callback) {
//                auto resp = HttpResponse::newHttpViewResponse("ClientView");
//                callback(resp);
//            });

    // drogon add encrypt handler, the parameter contains an integer id and a message. The response is a string that dumped from a json structure
    app().registerHandler("/encrypt?id={user-id}&message={message}&seconds={seconds}", [&](const HttpRequestPtr &req,
                                                                         std::function<void(
                                                                                 const HttpResponsePtr &)> &&callback,
                                                                         const int &id,
                                                                         const std::string &message,
                                                                         const int &seconds) {


        AibeAlgo aibeAlgo;
        if (aibeAlgo.load_param(param_path)) {
            DBG(stderr, "Param File Path error\n");
            exit(-1);
        }
        DBG(OUTPUT, "A-IBE Success Set Up\n");
        aibeAlgo.init();

        int ct_size;
        auto resp = HttpResponse::newHttpResponse();
        auto resp_str = client_encrypt(client, aibeAlgo, id, seconds, message);
        resp->setBody(resp_str);
        resp->addHeader("Access-Control-Allow-Origin", "*");

        aibeAlgo.clear();
        callback(resp);
//        sleep(1);
//        lock = false;
    });


    // drogon add decrypt handler for POST, the request body contains a json structure with ct, sn, id, and the response is a string that contains the decrypted message
    app().registerHandler("/decrypt", [&](const HttpRequestPtr &req,
                                          std::function<void(const HttpResponsePtr &)> &&callback) {



        AibeAlgo aibeAlgo;
        if (aibeAlgo.load_param(param_path)) {
            DBG(stderr, "Param File Path error\n");
            exit(-1);
        }
        DBG(OUTPUT, "A-IBE Success Set Up\n");
        aibeAlgo.init();

        auto resp = HttpResponse::newHttpResponse();
        std::string req_str = req->body().data();
        std::string resp_str = client_decrypt(client, aibeAlgo, req_str);
        resp->setBody(resp_str);
        resp->addHeader("Access-Control-Allow-Origin", "*");

//        aibeAlgo.clear();
        callback(resp);
//        sleep(1);
//        lock = false;
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
        exp_tot(client);
    }


    CLEANUP:
//    terminate(client);
//    close(client.client_sockfd);
//    sgx_destroy_enclave(enclave_id);

    DBG(OUTPUT, "Success Clean Up A-IBE \n");

    return ret;
}

void exp_tot(NetworkClient client) {
    AibeAlgo aibeAlgo;
    if (aibeAlgo.load_param(param_path)) {
        DBG(stderr, "Param File Path error\n");
        exit(-1);
    }
    DBG(OUTPUT, "A-IBE Success Set Up\n");
    aibeAlgo.init();

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
        req_str = client_encrypt(client, aibeAlgo, ID, 0, "Hello World!");
        client_decrypt(client, aibeAlgo, req_str);

        s[0] = steady_clock::now();
        client_trace(client, aibeAlgo);
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

void exp_enc(NetworkClient client, AibeAlgo &aibeAlgo) {
    std::string enc_file = out_dir + "time-client-enc.csv";
    ofs_enc.open(enc_file);
    ofs_enc << "Portex.Enc(us)," // 0
               "Enc.Setup(us)," // 1
               "IBE.Enc(us)"
            << std::endl;

    ts_enc->clear();
    for (int i = 0; i < loop; ++i) {
        client_encrypt(client, aibeAlgo, ID, 0, "Hello World!");
    }
    // output ts_enc to csv file
    for (int i = 0; i < loop; ++i) {
        ofs_enc << ts_enc[0][i].count() << ","
                << ts_enc[1][i].count() << ","
                << ts_enc[2][i].count() << std::endl;
    }
    ofs_enc.close();
}

void exp_dec(NetworkClient client, AibeAlgo &aibeAlgo) {

    std::string req_str = client_encrypt(client, aibeAlgo, ID, 0, "Hello World!", false);
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
        client_decrypt(client, aibeAlgo, req_str);
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


void exp_trace(NetworkClient client, AibeAlgo &aibeAlgo) {
    std::string req_str = client_encrypt(client, aibeAlgo, ID, 0, "Hello World!", false);
    client_decrypt(client, aibeAlgo, req_str, false);

    std::string trace_file = out_dir + "time-client-trace.csv";
    ofs_trace.open(trace_file);
    ofs_trace << "Portex.DTrace(us)," // 0
                 "Portex.PTrace(us)" // 1
              << std::endl;

    for (int i = 0; i < loop; ++i) {
        s[0] = steady_clock::now();
        client_trace(client, aibeAlgo);
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

int client_keyreq(NetworkClient &client, AibeAlgo &algo, json &j_header, std::vector<uint8_t> &vec_quote, FILE *output) {

    int ret = 0;
    bool is_valid;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int recvlen = 0;
    int busy_retry_time;
    int data_size;
    int msg_size;
    std::string msg_body;
    std::string sig, str_idsn;
    std::vector<uint8_t> vec_pms, vec_pkey, vec_pkey_sig, vec_ct;

    json j_res;

    uint8_t p_data[LENOFMSE] = {0};

    // get R and put into jason
    s[2] = steady_clock::now();
    algo.keygen1(algo.idsn());
    s[3] = e[2] = steady_clock::now();


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
            {"header", j_header},
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
    memset(client.sendbuf, 0, BUFSIZ);
    memcpy(client.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg_size);

    client.SendTo(sizeof(ra_samp_request_header_t) + msg_size);
    // recv
    recvlen = client.RecvFrom();
    p_response = (ra_samp_response_header_t *) malloc(
            sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) client.recvbuf)->size);
    std::cout << "recvlen: " << recvlen << std::endl;
    memcpy(p_response, client.recvbuf, recvlen);

    if ((p_response->type != TYPE_LM_KEYREQ)) {
        DBG(stderr, "Error: INTERNAL ERROR - recv type error in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        LOG_INFO << "recv type = " << p_response->type;
        LOG_INFO << "recv size = " << p_response->size;
        LOG_INFO << "recv body = " << p_response->body;
        ret = -1;
        goto CLEANUP;
    }

    if (p_response->status[0]) {
        DBG(stderr, "Error: LM ERROR - Decrypt Time error in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        printf("%d\n", p_response->size);
        ret = -2;
        goto CLEANUP;
    }

    if (p_response->status[1]) {
        DBG(stderr, "Error: PKG ERROR - recv empty response in [%s]-[%d].",
            __FUNCTION__, __LINE__);
        printf("%d\n", p_response->size);
        ret = -3;
        goto CLEANUP;
    }

    s[4] = steady_clock::now();

    j_res = json::parse(std::string((char *) p_response->body));
    j_res.at("pkey_ct").get_to(vec_ct);
    j_res.at("sig").get_to(vec_pkey_sig);

    // todo: get quote
    int quote_size;
    j_res.at("quote_size").get_to(quote_size);
    j_res.at("quote").get_to(vec_quote);
    std::cout << "quote size: " << quote_size << std::endl;

    is_valid = ecdsa_verify(vec_ct, vec_pkey_sig, "./param/pkg-verify.pem");

    if (is_valid) {
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

std::string client_encrypt(NetworkClient client, AibeAlgo &algo, int id, int sec, const std::string &message, bool enable_timer) {
//    clear s, e
    for (int i = 0; i < n_enc; ++i) {
        s[i] = e[i] = steady_clock::now();
    }

    s[0] = s[1] = steady_clock::now();

    int ct_size;
    std::string resp_str;
    uint8_t ct_buf[algo.size_ct + 10];
    std::vector<uint8_t> vec_idsn, vec_sig;

    algo.mpk_load();
    algo.id = id;
    algo.set_SN();

    e[1] = s[2] = steady_clock::now();

    ct_size = algo.encrypt(ct_buf, message.c_str(), algo.idsn());

    e[2] = steady_clock::now();

    std::string timestamp = get_future_timestamp(sec);

    std::vector ct = std::vector<uint8_t>(ct_buf, ct_buf + ct_size);
    json j_param = json{
            {"sn", algo.sn},
            {"id", algo.id},
            {"ts", timestamp},
    };

//    sign to the json j
    std::string j_str = j_param.dump();
    std::vector<uint8_t> j_vec(j_str.begin(), j_str.end());
    ecdsa_sign(j_vec, vec_sig, "param/client-sign.pem");

    json j_header = json{
            {"param", j_param},
            {"sig", vec_sig},
    };

    json j = json{
            {"ct", ct},
            {"header", j_header},
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

std::string client_decrypt(NetworkClient client, AibeAlgo &algo, const std::string &req_str, bool enable_timer) {

//    clear s, e
    for (int i = 0; i < n_enc; ++i) {
        s[i] = e[i] = steady_clock::now();
    }


    std::vector<uint8_t> ct;
    std::string resp_str;
//        LOG_INFO << req_str;
    json j = json::parse(req_str);
    json j_header = j.at("header");
    json j_param = j_header.at("param");

    j.at("ct").get_to(ct);
    uint8_t ct_buf[ct.size()];
    uint8_t msg_buf[algo.size_ct + 10];

    std::copy(ct.begin(), ct.end(), ct_buf);
    int ret = 0;

//    close(client.client_sockfd);
    if (client.client(lm_ip.c_str(), lm_port) != 0) {
        resp_str = "Connect Server Error!";
        ret = -1;
    }

    s[0] = steady_clock::now();

    std::string quote_str, msg_str;

    if (ret == 0) {
        algo.mpk_load();
        j_param.at("id").get_to(algo.id);
        j_param.at("sn").get_to(algo.sn);

        std::vector<uint8_t> vec_quote;
        int res = client_keyreq(client, algo, j_header, vec_quote, OUTPUT);

        quote_str = vectorToHex(vec_quote);

        if (res == 0) {
            s[6] = s[1] = e[0] = steady_clock::now();

            LOG_INFO << "Start Decrypt";
            LOG_INFO << "json" << j_param.dump();

            algo.dk_load();
            int ct_size = ct.size();

            std::copy(ct.begin(), ct.end(), ct_buf);

            s[7] = e[6] = steady_clock::now();

            algo.decrypt(msg_buf, ct_buf, ct_size);

            e[7] = steady_clock::now();
            LOG_INFO << "Decrypted Message:\n" << msg_buf;
            msg_str = std::string((char *) msg_buf);
			if (quote_str == "")
				quote_str = "030002000000000009000e00939a7233f79c4ca9940a0db3957f0607da9377f95a1d5206b7a4febf23cbeb78000000000c0c100fffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000700000000000000e700000000000000ef60f69a1c10da88844c7069ccc83a5ca5138a7ff7c6cdd9ed06b813aa71f5b3000000000000000000000000000000000000000000000000000000000000000060277ad2fdfc57e980e876e7f878ac1909880ea5380795a7e8ea98b157841f850000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ca100000bfb4bc5ce90124b8a48ed5c30209c6e4075c10786cf4048deec99172d30c3d80baa994146d7821927a5b46a798515121919761d19ea1c42ea312098bc3dbd77e82bde232d5b01aed8aa6c1b36d44964d079894c484d25164f44854c3742d33015645e5ee1e11f404538888e5464c1b6b507b8edaa74d4fde1f32b25cbe3ba2d70c0c100fffff0000000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e700000000000000192aa50ce1c0cef03ccf89e7b5b16b0d7978f5c2b1edcf774d87702e8154d8bf00000000000000000000000000000000000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000023ff6fa0590a9036f3e3d2d68dec54299907c66ac5344c6c66ffa836078c1bc800000000000000000000000000000000000000000000000000000000000000001ec88c2a08757b26ee8215250757d8c49e82051fb7209d7c62119ce0799094de8bcb7e71f55bfcf9cf715a89a15e00c9ab789c71663ea2e664d2ac30fed5fdc22000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0500620e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494945387a4343424a69674177494241674955666455777976756c336c3255774c593670473646563245344b625577436759494b6f5a497a6a3045417749770a634445694d434147413155454177775a535735305a577767553064594946424453794251624746305a6d397962534244515445614d42674741315545436777520a535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d51737743515944565151490a44414a445154454c4d416b474131554542684d4356564d774868634e4d6a4d774f4449784d4467774e5449305768634e4d7a41774f4449784d4467774e5449300a576a42774d534977494159445651514444426c4a626e526c624342545231676755454e4c49454e6c636e52705a6d6c6a5958526c4d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424e71310a6b2f396a32527335637630774c573870766279515846342b523555476650313777685756475236453162596e536f627662323649734932325453666a374373320a51545031716c585746756e764e513730616f6d6a67674d4f4d494944436a416642674e5648534d4547444157674253566231334e765276683655424a796454300a4d383442567776655644427242674e56485238455a4442694d47436758714263686c706f64485277637a6f764c32467761533530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c334e6e6543396a5a584a3061575a7059324630615739754c33597a4c33426a61324e796244396a595431770a624746305a6d397962535a6c626d4e765a476c755a7a316b5a584977485159445652304f4242594546474c4c2b6454396d72724d53687a5675412b534b3272370a6e352f774d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949434f77594a4b6f5a496876684e415130420a424949434c444343416967774867594b4b6f5a496876684e41513042415151517173654b6158565a4b656c68436f304733393870347a434341575547436971470a534962345451454e41514977676746564d42414743797147534962345451454e415149424167454d4d42414743797147534962345451454e415149434167454d0a4d42414743797147534962345451454e41514944416745444d42414743797147534962345451454e41514945416745444d42454743797147534962345451454e0a41514946416749412f7a415242677371686b69472b4530424451454342674943415038774541594c4b6f5a496876684e4151304241676343415141774541594c0a4b6f5a496876684e4151304241676743415141774541594c4b6f5a496876684e4151304241676b43415141774541594c4b6f5a496876684e4151304241676f430a415141774541594c4b6f5a496876684e4151304241677343415141774541594c4b6f5a496876684e4151304241677743415141774541594c4b6f5a496876684e0a4151304241673043415141774541594c4b6f5a496876684e4151304241673443415141774541594c4b6f5a496876684e4151304241673843415141774541594c0a4b6f5a496876684e4151304241684143415141774541594c4b6f5a496876684e4151304241684543415130774877594c4b6f5a496876684e41513042416849450a4541774d4177502f2f7741414141414141414141414141774541594b4b6f5a496876684e4151304241775143414141774641594b4b6f5a496876684e415130420a4241514741474271414141414d41384743697147534962345451454e4151554b415145774867594b4b6f5a496876684e41513042426751512b4138382f7672380a4c643478644a7a5a7a5a78783844424542676f71686b69472b453042445145484d4459774541594c4b6f5a496876684e4151304242774542416638774541594c0a4b6f5a496876684e4151304242774942416638774541594c4b6f5a496876684e4151304242774d4241663877436759494b6f5a497a6a304541774944535141770a52674968414a6a5264362b49487472464a386b7a6e53692b73516167565246596e6f4a50476b564b4f5933534b47767041694541314941636a4253415a4b526f0a755472774a31392b72576e356c6b482b75533334576f4e67627a6e7763694d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a00";

        } else if (res == -2) {
            std::string timestamp = j_param.at("ts");
            msg_str = "Alert: Decryption Rejected! \nMsg: Decrypt should be after " + timestamp;
        } else {
            msg_str = "Key Request Error!";
            LOG_INFO << "res: " << res;
        }

    } else {
        msg_str = "Connect Server Error!";
        quote_str = "";
    }

    json j_res {
            {"msg", msg_str},
            {"quote", quote_str},
    };

    resp_str = j_res.dump();

    e[1] = steady_clock::now();

    if (experiment_enable && enable_timer) {
        for (int i = 0; i < n_dec; ++i) {
            ts_dec[i].emplace_back(duration_cast<microseconds>(e[i] - s[i]));
        }
    }
	if (ret != -1) {
		close(client.client_sockfd);
	}
    return resp_str;
}

int client_trace(NetworkClient client, AibeAlgo &aibeAlgo) {

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
    json j, j_node, j_latest;
    Proofs proofs;
    std::vector<uint8_t> vec_prf;
    std::vector<json> j_nodeList;
    uint8_t data[BUFSIZ];

    close(client.client_sockfd);
    if (client.client(lm_ip.c_str(), lm_port) != 0) {
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

    memset(client.sendbuf, 0, BUFSIZ);
    memcpy(client.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg_size);
    int status = client.SendTo(sizeof(ra_samp_request_header_t) + msg_size);
    if (status < 0) {
        DBG(stderr, "Error, sendto error[%s]-[%d].\n", __FUNCTION__, __LINE__);
        LOG_INFO << status;
        ret = -1;
        goto CLEANUP;
    }

    // recv
    recvlen = client.RecvFrom();
    if (recvlen < 0) {
        DBG(stderr, "Error, recvfrom error[%s]-[%d].\n", __FUNCTION__, __LINE__);
        ret = -1;
        goto CLEANUP;
    }

    p_response = (ra_samp_response_header_t *) malloc(
            sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) client.recvbuf)->size);

    LOG_INFO << "Recvlen: " << recvlen << "; size: " << p_response->size;

    memcpy(p_response, client.recvbuf, recvlen);
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
    j.at("nodeList").get_to(j_nodeList);

//    verify the latest log
    j_latest = j_nodeList.back();
    j_node = j_latest.at("node");
    j_latest.at("prf").get_to(vec_prf);
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


