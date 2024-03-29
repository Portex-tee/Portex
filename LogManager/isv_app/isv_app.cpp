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

#include "aibe.h"
#include "ra.h"
#include "log.h"
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <json.hpp>
#include <drogon/HttpAppFramework.h>
#include "ec_crypto.h"
#include <chrono>
#include <csignal>

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

#define ENCLAVE_PATH "build/enclave.signed.so"

int experiment_enable(0);

const std::string out_dir = "/root/experiments/PortexData/testing-data/";
std::ofstream ofs_kreq, ofs_trace;

using json = nlohmann::json;
using namespace drogon;
using namespace std::chrono;
typedef time_point<steady_clock> ts;


int lm_port = 22333;
int pkg_port = 12333;
std::string pkg_ip = "127.0.0.1";

// experiments vars
const int n_trace = 2, n_kreq = 2;
std::vector<microseconds> ts_trace[n_trace], ts_kreq[n_kreq];
ts s[n_kreq], e[n_kreq];

LogTree logTree;
extern char sendbuf[BUFSIZ]; //数据传送的缓冲区
extern char recvbuf[BUFSIZ];

// This sample code doesn't have any recovery/retry mechanisms for the remote
// attestation. Since the enclave can be lost due S3 transitions, apps
// susceptible to S3 transitions should have logic to restart attestation in
// these scenarios.
#define _T(x) x


int lm_keyreq(const uint8_t *p_msg,
              uint32_t msg_size,
              sgx_enclave_id_t enclave_id,
              FILE *OUTPUT,
              NetworkClient &client,
              NetworkServer &server) {

    int ret = 0;
    uint8_t data[BUFSIZ];
    Proofs proofs;
    std::string encodedHexStr;
    ra_samp_request_header_t *p_request = NULL;
    ra_samp_response_header_t *p_response = NULL;
    int data_size, msg2_size, recvlen;
    std::vector<uint8_t> param_sig, vec_prf, vec_pms, ir, ir_sig;

    std::string j_str, ts, j_ts, str_sig;

    ts = get_timestamp();
    int id, sn;

    // parse json
    json json1;
    {
        std::string msg_body((char *) p_msg);
        std::cout << msg_body << std::endl;
        json1 = json::parse(msg_body);
    }

    json j_header = json1.at("header");
    json j_param = j_header.at("param");

    j_param.at("id").get_to(id);
    j_param.at("sn").get_to(sn);
    j_param.at("ts").get_to(j_ts);
    j_header.at("sig").get_to(param_sig);
    json1.at("pms").get_to(vec_pms);

    j_str = j_param.dump();
    std::vector<uint8_t> vec_param(j_str.begin(), j_str.end());
    bool is_valid = ecdsa_verify(vec_param, param_sig, "param/client-verify.pem");
    bool time_valid = compare_timestamps(j_ts, ts);

    s[1] = steady_clock::now();
    str_sig = vectorToHex(param_sig);
//        str_sig = wrapText(str_sig, 16);
    // construct node json
    json j_node{
            {"id",       id},
            {"sn",       sn},
            {"protocol", j_ts},
            {"ts",       ts},
            {"valid",    time_valid},
            {"sig",      str_sig},
    };

    // MT.Insert
    logTree.append(get_idsn(id, sn), j_node, proofs);
    LOG_INFO << "insert: id=" << id << ", sn=" << sn << ", idsn=" << get_idsn(id, sn);

    if (is_valid && time_valid) {

        // Parse proofs to json
        msg2_size = proofs.serialise(data);
        vec_prf = std::vector<uint8_t>(data, data + msg2_size);

        json j_req{
                {"prf", vec_prf},
                {"pms", vec_pms}
        };

        ir = json::to_bjdata(j_req);

        ecdsa_sign(ir, ir_sig, "param/lm-sign.pem");
        e[1] = steady_clock::now();

//        close(client.sockfd);
        if (client.client(pkg_ip.c_str(), pkg_port) != 0) {
            fprintf(OUTPUT, "Connect Server Error, Exit!\n");
            ret = -1;
            goto CLEANUP;
        }

        json j_body{
                {"ir",     j_req},
                {"ir_sig", ir_sig}
        };

        std::string str_body;
        str_body = j_body.dump();
        std::cout << str_body << std::endl;
        msg2_size = str_body.size() + 1;

        // send request to pkg
        p_request = (ra_samp_request_header_t *) malloc(sizeof(ra_samp_request_header_t) + msg2_size);
        p_request->type = TYPE_RA_KEYREQ;
        p_request->size = msg2_size;

        strcpy((char *) p_request->body, str_body.c_str());

        memset(client.sendbuf, 0, BUFSIZ);
        memcpy(client.sendbuf, p_request, sizeof(ra_samp_request_header_t) + msg2_size);
        client.SendTo(sizeof(ra_samp_request_header_t) + p_request->size);

        // recv
        recvlen = client.RecvFrom();
        p_response = (ra_samp_response_header_t *) malloc(
                sizeof(ra_samp_response_header_t) + ((ra_samp_response_header_t *) client.recvbuf)->size);

        memcpy(p_response, client.recvbuf, recvlen);
        if ((p_response->type != TYPE_RA_KEYREQ)) {
            fprintf(OUTPUT, "Error: INTERNAL ERROR - response type unmatched in [%s]-[%d].",
                    __FUNCTION__, __LINE__);
            ret = -1;
            goto CLEANUP;
        }
        std::cout << "certificate received" << std::endl;
        std::cout << "recvlen: " << recvlen << std::endl;


    } else {
        p_response = (ra_samp_response_header_t *) malloc(sizeof(ra_samp_response_header_t));

        // construct response
        memset(p_response, 0, sizeof(ra_samp_response_header_t));
        p_response->size = 0;
        p_response->status[0] = 1;
        p_response->status[1] = 0;

//        log_info output ts and j_ts
        LOG_INFO << "ts: " << ts << ", j_ts: " << j_ts;
        LOG_INFO << "is_valid: " << is_valid;
        LOG_INFO << "compare_timestamps: " << compare_timestamps(j_ts, ts);
    }

    p_response->type = TYPE_LM_KEYREQ;
    LOG_INFO << "response type = " << p_response->type;
    LOG_INFO << "response size = " << p_response->size;
    memset(server.sendbuf, 0, BUFSIZ);
    memcpy(server.sendbuf, p_response, sizeof(ra_samp_response_header_t) + p_response->size);
    server.SendTo(sizeof(ra_samp_response_header_t) + p_response->size);

//    assert(proofs.path->verify(proofs.root));

    CLEANUP:

    close(client.client_sockfd);
    SAFE_FREE(p_request);
    SAFE_FREE(p_response);
    return ret;
}

int lm_trace(const ra_samp_request_header_t *p_msg,
             uint32_t msg_size,
             sgx_enclave_id_t enclave_id,
             FILE *OUTPUT,
             NetworkServer &server) {


    int ret = 0;
    uint8_t data[BUFSIZ];
    std::vector<Proofs> proofsList;
    std::vector<LogNode> logNodeList;
    std::string encodedHexStr;
    ra_samp_response_header_t *p_response = NULL;
    int data_size, msg2_size, recvlen;

    int idsn = *((int *) p_msg);
    LOG_INFO << "idsn: " << idsn;

    std::string str_data;
    // log trace

    s[0] = steady_clock::now();
    if (logTree.trace(idsn, logNodeList, proofsList)) {
        std::vector<json> j_nodeList;
        for (int i = 0; i < logNodeList.size(); i++) {
            auto &logNode = logNodeList[i];
            auto &proofs = proofsList[i];
            json j_node = logNode.node;
            LOG_INFO << "trace: " << j_node.dump();


            // Parse proofs to json
            msg2_size = proofs.serialise(data);
            auto vec_prf = std::vector<uint8_t>(data, data + msg2_size);

            // construct response json
            json j_data = {
                    {"prf",  vec_prf},
                    {"node", j_node},
            };
            j_nodeList.push_back(j_data);
        }
        json j_body = {
                {"nodeList", j_nodeList}
        };
        str_data = j_body.dump();
        msg2_size = str_data.size() + 1;
        LOG_INFO << "response: size:" << msg2_size << "; Body size: " << str_data.length();

    } else {
        str_data = "";
        msg2_size = str_data.size() + 1;
    }
    e[0] = steady_clock::now();

    s[1] = steady_clock::now();
    logTree.chronTree.path(logNodeList.back().index);
    e[1] = steady_clock::now();


    // construct response
    p_response = (ra_samp_response_header_t *) malloc(sizeof(ra_samp_response_header_t) + msg2_size);
    p_response->type = TYPE_LM_TRACE;
    p_response->size = msg2_size;
    strcpy((char *) p_response->body, str_data.c_str());
    memset(server.sendbuf, 0, BUFSIZ);
    memcpy(server.sendbuf, p_response, sizeof(ra_samp_response_header_t) + p_response->size);
    server.SendTo(sizeof(ra_samp_response_header_t) + p_response->size);

    SAFE_FREE(p_response);

    return ret;
}

static void signalHandler(int signum) {
    // 处理 SIGINT 信号
    LOG_INFO << "接收到信号" << signum;

    //调用 app().quit()以退出Drogin应用程序
    exit(0);
}

void http_server() {
    std::cout << "Load http server" << std::endl;
    app().loadConfigFile("./config.json");

    app().registerHandler("/service", [&](const HttpRequestPtr &req,
                                          std::function<void(const HttpResponsePtr &)> &&callback) {
//                         LOG_INFO << "access /service";
        Json::Value data;
        Json::Reader reader;

//        parse the latest 20 nodes, in reverse order
        int n = logTree.nodeList.size();
        int start = n - 20;
        if (start < 0) {
            start = 0;
        }
        for (int i = n - 1; i >= start; i--) {
            Json::Value item;
            reader.parse(logTree.nodeList[i].node.dump(), item);
            data.append(item);
        }

        std::string resp_str = data.toStyledString();

        auto resp = HttpResponse::newHttpResponse();
        resp->setBody(resp_str);
        resp->addHeader("Access-Control-Allow-Origin", "*");
        callback(resp);
    });

//    app().enableDynamicViewsLoading({"views/"});

    LOG_INFO << "http server start";

    drogon::app().getLoop()->runAfter(0.0, [] { signal(SIGINT, signalHandler); });
    if (!experiment_enable) {
        drogon::app().run();
    }
}


int main(int argc, char *argv[]) {
//    if args has -t, set experiment_enable to 1
    if (argc > 1 && strcmp(argv[1], "-t") == 0) {
        experiment_enable = 1;
    }

    int ret = 0;
    sgx_enclave_id_t enclave_id = 0;
    FILE *OUTPUT = stdout;
    NetworkClient client;
    NetworkServer server;

    extern LogTree logTree;
    ra_samp_request_header_t *p_req;
    ra_samp_response_header_t **p_resp;
    ra_samp_response_header_t *p_resp_msg;
    int buflen = 0;

    Proofs proofs;
    std::string encodedHexStr;
    std::string srcStr;

    std::string kreq_file, trace_file;

    // todo: remove in release
    if (0) {
        std::cout << "Generate LM signing key pair (vk, sk)" << std::endl;
        ecdsa_kgen("../pkg/param/lm-verify.pem", "param/lm-sign.pem");
    }

    std::thread t1(http_server);


    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    memset(&launch_token, 0, sizeof(sgx_launch_token_t));
    {
        ret = sgx_create_enclave(_T(ENCLAVE_PATH),
                                 SGX_DEBUG_FLAG,
                                 &launch_token,
                                 &launch_token_update,
                                 &enclave_id, NULL);
        if (SGX_SUCCESS != ret) {
            std::cout << std::hex << ret << std::endl;
            ret = -1;
            fprintf(OUTPUT, "Error, call sgx_create_enclave fail [%s].\n",
                    __FUNCTION__);
            goto CLEANUP;
        }
        fprintf(OUTPUT, "Call sgx_create_enclave success.\n");
    }


    fprintf(OUTPUT, "start socket....\n");
    server.server(lm_port);

    if (experiment_enable) {
        kreq_file = out_dir + "time-lm-kreq.csv";
        trace_file = out_dir + "time-lm-trace.csv";
        ofs_kreq.open(kreq_file);
        ofs_trace.open(trace_file);
        ofs_kreq << "KReq.LM, KReq.LogGen" << std::endl;
        ofs_trace << "LogTrace, ProofGen" << std::endl;
    }

    do {
        bool is_recv = true;
        do {
            //阻塞调用socket
            buflen = server.RecvFrom();
            if (buflen > 0 && buflen < BUFSIZ) {
                p_req = (ra_samp_request_header_t *) malloc(buflen + 2);

                fprintf(OUTPUT, "Prepare receive struct\n");
                if (NULL == p_req) {
                    ret = -1;
                    goto CLEANUP;
                }
                memcpy(p_req, server.recvbuf, buflen);
                fprintf(OUTPUT, "request type is %d\n", p_req->type);
                switch (p_req->type) {
                    case TYPE_LM_KEYREQ:
                        fprintf(OUTPUT, "LM key request\n");

                        // SOCKET: connect to server


                        s[0] = steady_clock::now();

                        lm_keyreq((uint8_t *) p_req + sizeof(ra_samp_request_header_t),
                                  p_req->size,
                                  enclave_id,
                                  OUTPUT,
                                  client,
                                  server);

                        e[0] = steady_clock::now();

                        if (experiment_enable) {
                            for (int i = 0; i < n_kreq; ++i) {
                                ts_kreq[i].emplace_back(duration_cast<microseconds>(e[i] - s[i]));
                            }

                            // output ts_kreq to csv file
                            for (int i = 0; i < n_kreq; ++i) {
                                ofs_kreq << ts_kreq[i].back().count();
                                if (i != n_kreq - 1) {
                                    ofs_kreq << ", ";
                                } else {
                                    ofs_kreq << std::endl;
                                }
                            }
                        }

                        SAFE_FREE(p_req);
                        is_recv = false;
                        break;


                    case TYPE_LM_TRACE:
                        fprintf(OUTPUT, "LM trace request\n");

                        lm_trace((const ra_samp_request_header_t *) ((uint8_t *) p_req +
                                                                     sizeof(ra_samp_request_header_t)),
                                 p_req->size,
                                 enclave_id,
                                 OUTPUT,
                                 server);


                        if (experiment_enable) {
                            for (int i = 0; i < n_trace; ++i) {
                                ts_trace[i].emplace_back(duration_cast<microseconds>(e[i] - s[i]));
                            }

                            // output ts_trace to csv file
                            for (int i = 0; i < n_trace; ++i) {
                                ofs_trace << ts_trace[i].back().count();
                                if (i != n_trace - 1) {
                                    ofs_trace << ", ";
                                } else {
                                    ofs_trace << std::endl;
                                }
                            }
                        }

                        SAFE_FREE(p_req);
                        is_recv = false;
                        break;

                    default:
                        fprintf(stderr, "Error, unknown ra message type. Type = %d [%s].\n",
                                p_req->type, __FUNCTION__);
                        LOG_INFO << "Error, unknown ra message type. Type = " << p_req->type << " [" << __FUNCTION__
                                 << "].";
//                        output accept client info
                        LOG_INFO << "client ip: " << inet_ntoa(server.remote_addr.sin_addr) << ", port: "
                                 << ntohs(server.remote_addr.sin_port);

                        is_recv = false;
                        break;
                }
            }
        } while (is_recv);

        ret = server.accept_client();
        if (ret) {
            fprintf(OUTPUT, "Accept failed.\n");
            goto CLEANUP;
        }

    } while (true);


//    aibeAlgo.run(OUTPUT);

    //aibe load_param

    CLEANUP:

    app().quit();

    t1.join();
    terminate(client);
    server.Cleanupsocket();
    sgx_destroy_enclave(enclave_id);

    fprintf(OUTPUT, "Success Clean Up A-IBE ");

    return ret;
}
