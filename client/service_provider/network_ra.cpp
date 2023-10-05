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



#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "network_ra.h"
#include "service_provider.h"
//add
#include <string.h>


extern void PRINT_BYTE_ARRAY(
        FILE *file, void *mem, uint32_t len);
// Used to send requests to the service provider sample.  It
// simulates network communication between the ISV app and the
// ISV service provider.  This would be modified in a real
// product to use the proper IP communication.
//
// @param server_url String name of the server URL
// @param p_req Pointer to the message to be sent.
// @param p_resp Pointer to a pointer of the response message.

// @return int
// 修改成真正的网络通讯
int ra_network_send_receive(const char *server_url,
                            const ra_samp_request_header_t *p_req,
                            ra_samp_response_header_t **p_resp,
                            NetworkEnd &network) {
    FILE *OUTPUT = stdout;
    int ret = 0;
    int len = 0;
    int msg2len = 0;

    if ((NULL == server_url) ||
        (NULL == p_req) ||
        (NULL == p_resp)) {
        return -1;
    }
    switch (p_req->type) {

        case TYPE_RA_MSG0:
            memset(network.sendbuf, 0, BUFSIZ);
            memcpy_s(network.sendbuf, BUFSIZ, p_req, sizeof(ra_samp_request_header_t) + p_req->size);
            len = network.SendTo(sizeof(ra_samp_request_header_t) + p_req->size);
//            sleep(1);//等待起作用
            if (0 == len) {
                fprintf(stderr, "\nError,Send MSG0 fail [%s].",
                        __FUNCTION__);
            }
            break;

        case TYPE_RA_MSG1:
            memset(network.sendbuf, 0, BUFSIZ);
            memcpy_s(network.sendbuf, BUFSIZ, p_req, sizeof(ra_samp_request_header_t) + p_req->size);
            ret = network.SendTo(sizeof(ra_samp_request_header_t) + p_req->size);
            fprintf(stdout, "\nSend MSG1 To Server [%s].", __FUNCTION__);
            ret = network.RecvFrom();
            msg2len = sizeof(ra_samp_response_header_t) + sizeof(sample_ra_msg2_t);

            memcpy_s(*p_resp, msg2len, network.recvbuf, ret);
            break;

        case TYPE_RA_MSG3:
            memset(network.sendbuf, 0, BUFSIZ);
            memcpy_s(network.sendbuf, BUFSIZ, p_req, sizeof(ra_samp_request_header_t) + p_req->size);
            ret = network.SendTo(sizeof(ra_samp_request_header_t) + p_req->size);
            ret = network.RecvFrom();
            memcpy_s(*p_resp, ret, network.recvbuf, ret);
            fprintf(stderr, "\nMsg3 ret = %d [%s].", ret);
            PRINT_BYTE_ARRAY(OUTPUT, *p_resp, ret);
            break;

        default:
            ret = -1;
            fprintf(stderr, "\nError, unknown ra message type. Type = %d [%s].",
                    p_req->type, __FUNCTION__);
            break;
    }

    return ret;
}

// Used to free the response messages.  In the sample code, the
// response messages are allocated by the SP code.
//
//
// @param resp Pointer to the response buffer to be freed.

void ra_free_network_response_buffer(ra_samp_response_header_t *resp) {
    if (resp != NULL) {
        free(resp);
    }
}

int NetworkClient::client(const char *ip, int port) {
    int len;
    struct sockaddr_in remote_addr; //服务器端网络地址结构体
    memset(&remote_addr, 0, sizeof(remote_addr)); //数据初始化--清零
    remote_addr.sin_family = AF_INET; //设置为IP通信
    remote_addr.sin_addr.s_addr = inet_addr(ip);//服务器IP地址
    remote_addr.sin_port = htons(port); //服务器端口号

    /*创建客户端套接字--IPv4协议，面向连接通信，TCP协议*/
    if ((client_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    /*将套接字绑定到服务器的网络地址上*/
    if (connect(client_sockfd, (struct sockaddr *) &remote_addr, sizeof(remote_addr)) < 0) {
        perror("connect");
//        wait 1 second
        return 1;
    }
    printf("connected to server\n");
    return 0;
}

int NetworkEnd::SendTo(int len) {
    len = send(client_sockfd, sendbuf, len, 0);//发送
}

int NetworkEnd::RecvFrom() {
    /*接收服务端的数据*/
    int len = 0;
//    receive all data
    while (len < BUFSIZ) {
        int ret = recv(client_sockfd, recvbuf + len, BUFSIZ - len, 0);
        if (ret <= 0) {
            break;
        }
        len += ret;
    }

    return len;
}

int NetworkEnd::Cleanupsocket() {
    close(sockfd);
    return 0;
}

int NetworkServer::server(int port) {
    FILE *OUTPUT = stdout;
    int len;
    socklen_t sin_size;
    sin_size = sizeof(struct sockaddr_in);

    memset(&my_addr, 0, sizeof(my_addr)); //数据初始化--清零
    my_addr.sin_family = AF_INET; //设置为IP通信
    my_addr.sin_addr.s_addr = INADDR_ANY;//服务器IP地址--允许连接到所有本地地址上
    my_addr.sin_port = htons(port); //服务器端口号

    /*创建服务器端套接字--IPv4协议，面向连接通信，TCP协议*/
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    /*将套接字绑定到服务器的网络地址上*/
    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr)) < 0) {
        perror("bind");
        return 1;
    }

    /*监听连接请求--监听队列长度为5*/
    fprintf(OUTPUT, "\nlistening...");
    listen(sockfd, 5);

    sin_size = sizeof(struct sockaddr_in);

    /*等待客户端连接请求到达*/
    if ((client_sockfd = accept(sockfd, (struct sockaddr *) &remote_addr, &sin_size)) < 0) {
        perror("accept");
        return 1;
    }
    fprintf(OUTPUT, "\naccepted\n");

    return 0;
}

int NetworkServer::accept_client() {
    FILE *OUTPUT = stdout;
    socklen_t sin_size;
    sin_size = sizeof(struct sockaddr_in);

    close(client_sockfd);
    /*等待客户端连接请求到达*/
    if ((client_sockfd = accept(sockfd, (struct sockaddr *) &remote_addr, &sin_size)) < 0) {
        perror("accept");
        return 1;
    }
    fprintf(OUTPUT, "\naccepted\n");
    return 0;
}
