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

    FILE *OUTPUT = stdout;


    //aibe setup
    pairing_t pairing;
    char param[1024];
    FILE *param_file = fopen(file_path, "r");
    size_t count = fread(param, sizeof(char), 1024, param_file);
    if (!count) {
        pbc_die("param file path error");
    }
    pairing_init_set_buf(pairing, param, count);

    fprintf(OUTPUT, "\nA-IBE Success Set Up");

////aibe: init

    // param elements
    element_t x;
    element_t g;
    mpk_t mpk;

    // user elements
    element_t Hz;
    element_t t0;
    element_t theta;
    element_t R;
    element_t r;
    element_t r2; // r''
    element_t el;
    element_t er;

    // pkg elements
    element_t r1; // r'
    element_t t1;
    dk_t dk; // d_ID
    dk_t dk1; // d'_ID

    // temp elements
    element_t tz;
    element_t tg;
    element_t te;

//    element init
    element_init_Zr(x, pairing);
    element_init_G2(g, pairing);
    mpk_init(&mpk, pairing);

    element_init_G1(Hz, pairing);
    element_init_Zr(t0, pairing);
    element_init_Zr(theta, pairing);
    element_init_G1(R, pairing);
    element_init_Zr(r, pairing);
    element_init_Zr(r2, pairing);
    element_init_GT(el, pairing);
    element_init_GT(er, pairing);

    element_init_Zr(r1, pairing);
    element_init_Zr(t1, pairing);
    dk_init(&dk, pairing);
    dk_init(&dk1, pairing);

    element_init_Zr(tz, pairing);
    element_init_G1(tg, pairing);
    element_init_GT(te, pairing);


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


    // todo: mpk setup

    fprintf(OUTPUT, "\nA-IBE Success Init ");

    // SOCKET: connect to server
    if (remote_attestation(enclave_id, "127.0.0.1", 12333) != SGX_SUCCESS)
    {
        fprintf(OUTPUT, "Remote Attestation Error, Exit!\n");
        return -1;
    }

    ra_encrypt(enclave_id, OUTPUT);

////todo: server aibe setup

        element_random(g);
        element_random(mpk.h);
        element_random(mpk.Y);
        element_random(x);
        for (int i = 0; i < N; ++i) {
            element_random(mpk.Z[i]);
        }
        element_pow_zn(mpk.X, g, x);

        puts("\npkg: setup finished");


////aibe: keygen1

        element_random(t0);
        element_random(theta);

        element_set(Hz, mpk.Z[0]);

        {
            mpz_t digit;
            for (int i = 1; i <= z_size; ++i) {
                mpz_init_set_si(digit, get_bit(ID, i));
                if (!mpz_is0(digit))
                    element_mul(Hz, Hz, mpk.Z[i]);
                mpz_clear(digit);
            }
        }

        // R = h^t0 * X^theta
        element_pow_zn(R, mpk.h, t0);
        element_pow_zn(tg, mpk.X, theta);
        element_mul(R, R, tg);

        fprintf(OUTPUT, "\nA-IBE Success Keygen1 ");

////todo: server aibe keygen2

        element_random(r1);
        element_random(t1);

        //  d1 = (Y * R * h^t1)^(1/x) * Hz^r1
        //      d1 = Y * R
        element_mul(dk1.d1, mpk.Y, R);
        //      d1 = d1 * h^t1
        element_pow_zn(tg, mpk.h, t1);
        element_mul(dk1.d1, dk1.d1, tg);
        //      d1 = d1 ^ (1/x)
        element_invert(tz, x);
        element_pow_zn(dk1.d1, dk1.d1, tz);
        //      d1 = d1 * Hz^r1;
        element_pow_zn(tg, Hz, r1);
        element_mul(dk1.d1, dk1.d1, tg);
        // d2 = X^r1
        element_pow_zn(dk1.d2, mpk.X, r1);
        // d3 = t1
        element_set(dk1.d3, t1);

        puts("\npkg: keygen2 finished");

////aibe: keygen3

        element_random(r2);
        element_add(r, r1, r2);
        //  d1 = d1' / g^theta * Hz^r2
        //      d1 = d1' / g^theta
        element_pow_zn(tg, g, theta);
        element_div(dk.d1, dk1.d1, tg);
        //      d1 = d1 * Hz^r2
        element_pow_zn(tg, Hz, r2);
        element_mul(dk.d1, dk.d1, tg);
        //  d2 = d2' * X^r2
        element_pow_zn(tg, mpk.X, r2);
        element_mul(dk.d2, dk1.d2, tg);
        //  d3 = d3' + t0
        element_add(dk.d3, dk1.d3, t0);

        //  el = e(d1, X)
        element_pairing(el, dk.d1, mpk.X);
        //  er = e(Y, g)
        element_pairing(er, mpk.Y, g);
        //  er = er * e(h, g)^d3
        element_pairing(te, mpk.h, g);
        element_pow_zn(te, te, dk.d3);
        element_mul(er, er, te);
        //  er = er * e(Hz, d2)
        element_pairing(te, Hz, dk.d2);
        element_mul(er, er, te);

        if (element_cmp(el, er)) {
            puts("invalid key");
        } else {
            puts("valid key");
        }

        fprintf(OUTPUT, "\nA-IBE Success Keygen3 ");
    //todo: aibe clear

CLEANUP:
    Cleanupsocket();
    sgx_destroy_enclave(enclave_id);

////    element clear
    // find: element_init_([a-zA-Z0-9]*)\(([a-zA-Z0-9.\[\]]+), ([a-zA-Z]+)\)
    // repl: element_clear($2)
    element_clear(x);
    element_clear(g);
    mpk_clear(&mpk);

    element_clear(Hz);
    element_clear(t0);
    element_clear(theta);
    element_clear(R);
    element_clear(r);
    element_clear(r2);
    element_clear(el);
    element_clear(er);

    element_clear(r1);
    element_clear(t1);
    dk_clear(&dk);
    dk_clear(&dk1);

    element_clear(tz);
    element_clear(tg);
    element_clear(te);

    fprintf(OUTPUT, "\nSuccess Clean Up A-IBE ");

    return ret;
}
