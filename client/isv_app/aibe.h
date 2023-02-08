//
// Created by jojjiw on 2022/3/17.
//

#ifndef PBC_TEST_AIBE_H
#define PBC_TEST_AIBE_H

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <cmath>

#define N ((int)(1 << 4))
#define BLOCK_MAX 8

const int z_size = N + 1;
const int ID = 0b10101010;
const char param_path[] = "param/aibe.param";
const char mpk_path[] = "param/mpk.out";
const char msk_path[] = "param/msk.out";
const char dk_path[] = "param/dk.out";
const char ct_path[] = "ct.out";
const char msg_path[] = "msg.txt";
const char out_path[] = "out.txt";


typedef struct mpk_t {
    element_t X, Y, h, Z[N + 1];
} mpk_t;

typedef struct dk_t {
    element_t d1, d2, d3; // G1, G1, Zr
} dk_t;

typedef struct ct_t {
    element_t c1, c2, c3, c4; // G1, G1, GT, GT
};

void ct_init(ct_t *ct, pairing_t pairing);

void ct_clear(ct_t *ct);

void mpk_init(mpk_t *mpk, pairing_t pairing);

void mpk_clear(mpk_t *mpk);

void dk_init(dk_t *dk, pairing_t pairing);

void dk_clear(dk_t *dk);

void dk_to_bytes(uint8_t *data, dk_t *dk, int size_comp_G1);

void dk_from_bytes(dk_t *dk, uint8_t *data, int size_comp_G1);

int get_bit(int id, int n);

void data_xor(uint8_t *out, const uint8_t *d1, const uint8_t *d2, int size);

class AibeAlgo {
public:

    // param elements
    element_t x; // Zr
    element_t g; // G2
    mpk_t mpk;

    // user elements
    element_t Hz; // G1
    element_t t0; // Zr
    element_t theta; // Zr
    element_t R; // G1
    element_t r; // Zr
    element_t r2; // Zr: r''
    element_t el; // GT
    element_t er; // GT
    element_t m;
    ct_t ct;

    // pkg elements
    element_t r1; // Zr: r'
    element_t t1; // Zr
    dk_t dk; // d_ID
    dk_t dk1; // d'_ID
    dk_t dk2; // compare dk

    // temp elements
    element_t tz; // Zr
    element_t tg; // G1
    element_t te; // GT

    pairing_t pairing;

    int size_comp_G1, size_comp_G2, size_Zr, size_GT, size_block, size_ct_block, size_ct, size_msg_block;

    AibeAlgo(){};

    int run(FILE *OUTPUT);

    int load_param(const char *fn);

    void pkg_setup_generate();

    void pkg_setup_generate(const char *pk_path, const char *sk_path);

    void msk_load();

    void mpk_load();

    void dk_store();

    void dk_load();

    void dk2_load(const std::string& dk2_path);

    bool dk_verify();

    bool dk_verify(dk_t &dkt);

    void init();

    void set_Hz(int id);

    void keygen1(int id);

    void keygen2();

    int keygen3();

    int block_encrypt(int id);

    int block_decrypt();

    void clear();

    void ct_store(uint8_t *buf);

    void ct_load(uint8_t *buf);

    int encrypt(uint8_t *ct_buf, const char *str, int id);

    void decrypt(uint8_t *msg, uint8_t *data, int size);
};


int get_bit(int id, int n) {
    return (id >> (N - n)) & 1;
}

void ct_init(ct_t *ct, pairing_t pairing) {
    element_init_G1(ct->c1, pairing);
    element_init_G1(ct->c2, pairing);
    element_init_GT(ct->c3, pairing);
    element_init_GT(ct->c4, pairing);
}

void ct_clear(ct_t *ct) {
    element_clear(ct->c1);
    element_clear(ct->c2);
    element_clear(ct->c3);
    element_clear(ct->c4);
}

void mpk_init(mpk_t *mpk, pairing_t pairing) {
    element_init_G1(mpk->h, pairing);
    element_init_G1(mpk->X, pairing);
    element_init_G1(mpk->Y, pairing);
    for (int i = 0; i <= N; ++i) {
        element_init_G1(mpk->Z[i], pairing);
    }
}

void mpk_clear(mpk_t *mpk) {
    element_clear(mpk->h);
    element_clear(mpk->X);
    element_clear(mpk->Y);
    for (int i = 0; i <= N; ++i) {
        element_clear(mpk->Z[i]);
    }
}

void dk_init(dk_t *dk, pairing_t pairing) {
    element_init_G1(dk->d1, pairing);
    element_init_G1(dk->d2, pairing);
    element_init_Zr(dk->d3, pairing);
}

void dk_clear(dk_t *dk) {
    element_clear(dk->d1);
    element_clear(dk->d2);
    element_clear(dk->d3);
}

void dk_to_bytes(uint8_t *data, dk_t *dk, int size_comp_G1) {
    element_to_bytes_compressed(data, dk->d1);
    element_to_bytes_compressed(data + size_comp_G1, dk->d2);
    element_to_bytes(data + size_comp_G1 * 2, dk->d3);
}

void dk_from_bytes(dk_t *dk, uint8_t *data, int size_comp_G1) {
    element_from_bytes_compressed(dk->d1, data);
    element_from_bytes_compressed(dk->d2, data + size_comp_G1);
    element_from_bytes(dk->d3, data + size_comp_G1 * 2);
}

int AibeAlgo::run(FILE *OUTPUT) {

    int ret = 0;

    //aibe load_param

    if (load_param(param_path)) {
        ret = -1;
        fprintf(stderr, "\nParam File Path error");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "\nA-IBE Success Set Up");

////    element init
    init();

    mpk_load();
    msk_load();

    puts("\nPKG: setup finished");

////    aibe: keygen1

    keygen1(ID);
    fprintf(OUTPUT, "\nA-IBE Success Keygen1 ");

    keygen2();
    puts("\nPKG: keygen2 finished");

////    aibe: keygen3
    if (keygen3()) {
        fprintf(stderr, "\nKey verify failed");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "\nA-IBE Success Keygen3 ");

////    element clear
    CLEANUP:

    clear();
    fprintf(OUTPUT, "\nSuccess Clean Up A-IBE ");
    return ret;

}

int AibeAlgo::load_param(const char *fn) {
    int ret = 0;
    char param[10240];
    FILE *param_file = fopen(fn, "r");
    size_t count = fread(param, sizeof(char), 10240, param_file);
    if (!count) {
        ret = -1;
        goto CLEANUP;
    }
    fclose(param_file);
    pairing_init_set_buf(pairing, param, count);

    size_comp_G1 = pairing_length_in_bytes_compressed_G1(pairing);
    size_comp_G2 = pairing_length_in_bytes_compressed_G2(pairing);
    size_GT = pairing_length_in_bytes_GT(pairing);
    size_Zr = pairing_length_in_bytes_Zr(pairing);
    size_ct_block = size_comp_G1 * 2 + size_GT * 2;
    size_msg_block = size_GT;
    size_block = size_msg_block + size_ct_block;
    size_ct = BLOCK_MAX * size_block;

    CLEANUP:
    return ret;
}

void AibeAlgo::init() {

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
    element_init_GT(m, pairing);
    ct_init(&ct, pairing);

    element_init_Zr(r1, pairing);
    element_init_Zr(t1, pairing);
    dk_init(&dk, pairing);
    dk_init(&dk1, pairing);
    dk_init(&dk2, pairing);

    element_init_Zr(tz, pairing);
    element_init_G1(tg, pairing);
    element_init_GT(te, pairing);

}

void AibeAlgo::pkg_setup_generate(const char *pk_path, const char *sk_path) {

    FILE *fpk = fopen(pk_path, "w+");
    FILE *fsk = fopen(sk_path, "w+");

    element_random(g);
    element_random(mpk.h);
    element_random(mpk.Y);
    element_random(x);
    for (int i = 0; i < N; ++i) {
        element_random(mpk.Z[i]);
    }
    element_pow_zn(mpk.X, g, x);

    uint8_t buffer[1024];

    element_to_bytes_compressed(buffer, g);
    fwrite(buffer, size_comp_G2, 1, fpk);
    element_to_bytes_compressed(buffer, mpk.X);
    fwrite(buffer, size_comp_G1, 1, fpk);
    element_to_bytes_compressed(buffer, mpk.Y);
    fwrite(buffer, size_comp_G1, 1, fpk);
    element_to_bytes_compressed(buffer, mpk.h);
    fwrite(buffer, size_comp_G1, 1, fpk);
    for (int i = 0; i < N; ++i) {
        element_to_bytes_compressed(buffer, mpk.Z[i]);
        fwrite(buffer, size_comp_G1, 1, fpk);
    }

    element_to_bytes(buffer, x);
    fwrite(buffer, size_Zr, 1, fsk);

//    element_printf("%B\n", g);
//    element_printf("%B\n", mpk.X);
//    element_printf("%B\n", mpk.Y);
//    element_printf("%B\n", mpk.h);
//    for (int i = 0; i < N; ++i) {
//        element_printf("%B\n", mpk.Z[i]);
//    }
//    element_printf("%B\n", x);

    fclose(fpk);
    fclose(fsk);
}

void AibeAlgo::pkg_setup_generate() {
    pkg_setup_generate(mpk_path, msk_path);
}

void AibeAlgo::mpk_load() {
    FILE *fpk = fopen(mpk_path, "r+");

    char buffer[10240];

    fread(buffer, size_comp_G2, 1, fpk);
    element_from_bytes_compressed(g, (unsigned char *) buffer);
    fread(buffer, size_comp_G1, 1, fpk);
    element_from_bytes_compressed(mpk.X, (unsigned char *) buffer);
    fread(buffer, size_comp_G1, 1, fpk);
    element_from_bytes_compressed(mpk.Y, (unsigned char *) buffer);
    fread(buffer, size_comp_G1, 1, fpk);
    element_from_bytes_compressed(mpk.h, (unsigned char *) buffer);

    for (int i = 0; i < N; ++i) {
        fread(buffer, size_comp_G1, 1, fpk);
        element_from_bytes_compressed(mpk.Z[i], (unsigned char *) buffer);
    }

    // test
//    element_printf("%B\n", g);
//    element_printf("%B\n", mpk.X);
//    element_printf("%B\n", mpk.Y);
//    element_printf("%B\n", mpk.h);
//    for (int i = 0; i < N; ++i) {
//        element_printf("%B\n", mpk.Z[i]);
//    }
//    element_printf("%B\n", x);

    fclose(fpk);
}

void AibeAlgo::msk_load() {
    FILE *fsk = fopen(msk_path, "r+");

    char buffer[1024];

    fread(buffer, size_Zr, 1, fsk);
    element_from_bytes(x, (unsigned char *) buffer);

    fclose(fsk);
}

void AibeAlgo::set_Hz(int id) {

    element_set(Hz, mpk.Z[0]);
    {
        mpz_t digit;
        for (int i = 1; i <= z_size; ++i) {
            mpz_init_set_si(digit, get_bit(id, i));
            if (!mpz_is0(digit))
                element_mul(Hz, Hz, mpk.Z[i]);
            mpz_clear(digit);
        }
    }

}

// client keygen 1
void AibeAlgo::keygen1(const int id) {
    element_random(t0);
    element_random(theta);

    set_Hz(id);

    // R = h^t0 * X^theta
    element_pow_zn(R, mpk.h, t0);
    element_pow_zn(tg, mpk.X, theta);
    element_mul(R, R, tg);
}

// pkg keygen 2
void AibeAlgo::keygen2() {
    element_random(r1);
    element_random(t1);

    //  d1 = (Y * _R * h^t1)^(1/x) * _Hz^r1
    //      d1 = Y * _R
    element_mul(dk1.d1, mpk.Y, R);
    //      d1 = d1 * h^t1
    element_pow_zn(tg, mpk.h, t1);
    element_mul(dk1.d1, dk1.d1, tg);
    //      d1 = d1 ^ (1/x)
    element_invert(tz, x);
    element_pow_zn(dk1.d1, dk1.d1, tz);
    //      d1 = d1 * _Hz^r1;
    element_pow_zn(tg, Hz, r1);
    element_mul(dk1.d1, dk1.d1, tg);
    // d2 = X^r1
    element_pow_zn(dk1.d2, mpk.X, r1);
    // d3 = t1
    element_set(dk1.d3, t1);
}

// client keygen 3
int AibeAlgo::keygen3() {
    int ret = 0;

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

    if(!dk_verify()) {
        ret =-1;
    }
    return ret;

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
        ret = -1;
    }
    return ret;
}

void AibeAlgo::clear() {
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
    element_clear(m);
    ct_clear(&ct);

    element_clear(r1);
    element_clear(t1);
    dk_clear(&dk);
    dk_clear(&dk1);

    element_clear(tz);
    element_clear(tg);
    element_clear(te);

}

void AibeAlgo::dk_store() {
    FILE *f = fopen(dk_path, "w+");
    uint8_t buffer[1024];

    element_to_bytes_compressed(buffer, dk.d1);
    fwrite(buffer, size_comp_G1, 1, f);
    element_to_bytes_compressed(buffer, dk.d2);
    fwrite(buffer, size_comp_G1, 1, f);
    element_to_bytes(buffer, dk.d3);
    fwrite(buffer, size_Zr, 1, f);

    fclose(f);
}

void AibeAlgo::dk_load() {
    FILE *f = fopen(dk_path, "r+");
    char buffer[1024];

    fread(buffer, size_comp_G1, 1, f);
    element_from_bytes_compressed(dk.d1, (unsigned char *) buffer);
    fread(buffer, size_comp_G1, 1, f);
    element_from_bytes_compressed(dk.d2, (unsigned char *) buffer);
    fread(buffer, size_Zr, 1, f);
    element_from_bytes(dk.d3, (unsigned char *) buffer);

    fclose(f);
}

void AibeAlgo::dk2_load(const std::string& dk2_path) {
    FILE *f = fopen(dk2_path.c_str(), "r+");
    char buffer[1024];

    fread(buffer, size_comp_G1, 1, f);
    element_from_bytes_compressed(dk2.d1, (unsigned char *) buffer);
    fread(buffer, size_comp_G1, 1, f);
    element_from_bytes_compressed(dk2.d2, (unsigned char *) buffer);
    fread(buffer, size_Zr, 1, f);
    element_from_bytes(dk2.d3, (unsigned char *) buffer);

    fclose(f);
}

void AibeAlgo::ct_store(uint8_t *buf) {
    int it = 0;
    element_to_bytes_compressed(buf + it, ct.c1);
    it += size_comp_G1;
    element_to_bytes_compressed(buf + it, ct.c2);
    it += size_comp_G1;
    element_to_bytes(buf + it, ct.c3);
    it += size_GT;
    element_to_bytes(buf + it, ct.c4);
    it += size_GT;
}

void AibeAlgo::ct_load(uint8_t *buf) {
    int it = 0;
    element_from_bytes_compressed(ct.c1, (unsigned char *) buf + it);
    it += size_comp_G1;
    element_from_bytes_compressed(ct.c2, (unsigned char *) buf + it);
    it += size_comp_G1;
    element_from_bytes(ct.c3, (unsigned char *) buf + it);
    it += size_GT;
    element_from_bytes(ct.c4, (unsigned char *) buf + it);
    it += size_GT;
}

int AibeAlgo::block_encrypt(int id) {
    element_t s;
    element_init_Zr(s, pairing);
    element_random(s);

    element_pow_zn(ct.c1, mpk.X, s);

    element_set(Hz, mpk.Z[0]);
    {
        mpz_t digit;
        for (int i = 1; i <= z_size; ++i) {
            mpz_init_set_si(digit, get_bit(id, i));
            if (!mpz_is0(digit))
                element_mul(Hz, Hz, mpk.Z[i]);
            mpz_clear(digit);
        }
    }
    element_pow_zn(ct.c2, Hz, s);

    element_pairing(ct.c3, g, mpk.h);
    element_pow_zn(ct.c3, ct.c3, s);

    element_pairing(ct.c4, g, mpk.Y);
    element_pow_zn(ct.c4, ct.c4, s);
    element_mul(ct.c4, m, ct.c4);

    element_clear(s);

    return 0;
}

int AibeAlgo::block_decrypt() {

    element_t ele_gt1;
    element_t ele_gt2;
    element_init_GT(ele_gt1, pairing);
    element_init_GT(ele_gt2, pairing);

    element_pairing(ele_gt1, ct.c2, dk.d2);
    element_pow_zn(ele_gt2, ct.c3, dk.d3);
    element_mul(ele_gt1, ele_gt1, ele_gt2);
    element_pairing(ele_gt2, ct.c1, dk.d1);
    element_div(ele_gt1, ele_gt1, ele_gt2);

    element_mul(m, ct.c4, ele_gt1);

    element_clear(ele_gt1);
    element_clear(ele_gt2);

    return 0;
}

int AibeAlgo::encrypt(uint8_t *ct_buf, const char *str, int id) {
    int len = strlen(str);
    int block_num = (len % size_msg_block) ? len / size_msg_block + 1: len / size_msg_block;
    uint8_t strbuf[block_num * size_msg_block];

    memset(strbuf, 0, sizeof(strbuf));
    strcpy((char *)strbuf, str);

    for (int i = 0; i < block_num; ++i) {
        element_random(m);
        block_encrypt(id);
        element_to_bytes(ct_buf + i * size_block, m);
        data_xor(ct_buf + i * size_block, strbuf + i * size_msg_block, ct_buf + i * size_block, size_msg_block);
        ct_store(ct_buf + i * size_block + size_msg_block);
    }

    return block_num * size_block;
}

void AibeAlgo::decrypt(uint8_t *msg, uint8_t *data, int size) {
    int block_num = size / size_block;

    for (int i = 0; i < block_num; ++i) {
        ct_load(data + i * size_block + size_msg_block);
        block_decrypt();
        element_to_bytes(msg + i * size_msg_block, m);
        data_xor(msg + i * size_msg_block, msg + i * size_msg_block, data + i * size_block, size_msg_block);
    }

    msg[block_num * size_msg_block] = '\0';

//    printf("%s\n", msg);
}


bool AibeAlgo::dk_verify() {
    return dk_verify(dk);
}

bool AibeAlgo::dk_verify(dk_t &dkt) {
    element_pairing(el, dkt.d1, mpk.X);
    //  er = e(Y, g)
    element_pairing(er, mpk.Y, g);
    //  er = er * e(h, g)^d3
    element_pairing(te, mpk.h, g);
    element_pow_zn(te, te, dkt.d3);
    element_mul(er, er, te);
    //  er = er * e(Hz, d2)
    element_pairing(te, Hz, dkt.d2);
    element_mul(er, er, te);


//    element_printf("%B\n", mpk.X);
//    element_printf("%B\n", mpk.Y);
//    element_printf("%B\n", g);
//    element_printf("%B\n", dkt.d1);
//    element_printf("%B\n", dkt.d2);
//    element_printf("%B\n", dkt.d3);
//    element_printf("%B\n", Hz);
//    element_printf("left: %B, right: %B\n", el, er);

    return element_cmp(el, er) == 0;
}


void data_xor(uint8_t *out, const uint8_t *d1, const uint8_t *d2, int size) {
    uint8_t buffer[size];
    for (int i = 0; i < size; ++i) {
        buffer[i] = d1[i] ^ d2[i];
    }
    memcpy(out, buffer, size);
}

#endif //PBC_TEST_AIBE_H
