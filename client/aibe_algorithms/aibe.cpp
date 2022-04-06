
#include <stdio.h>

#include "aibe.h"


int get_bit(int id, int n) {
    return (id >> (N - n)) & 1;
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

int AibeAlgo::run(FILE *OUTPUT) {

    int ret = 0;

    //aibe load_param

    if (!load_param(file_path)) {
        ret = -1;
        fprintf(stderr, "\nParam File Path error");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "\nA-IBE Success Set Up");

////    element init
    init();

////    todo: server aibe load_param
    server_setup();

    puts("\nPKG: setup finished");

////    aibe: keygen1

    keygen1(ID);
    fprintf(OUTPUT, "\nA-IBE Success Keygen1 ");

////    todo: server aibe keygen2
    keygen2();
    puts("\nPKG: keygen2 finished");

////    aibe: keygen3
    if (!keygen3()) {
        fprintf(stderr, "\nKey verify failed");
        goto CLEANUP;
    }

    fprintf(OUTPUT, "\nA-IBE Success Keygen3 ");
    //todo: aibe clear

////    element clear
CLEANUP:

    clear();
    fprintf(OUTPUT, "\nSuccess Clean Up A-IBE ");
    return ret;

}

int AibeAlgo::load_param(const char *fn) {
    int ret = 0;
    char param[1024];
    FILE *param_file = fopen(fn, "r");
    puts("file opened");
    size_t count = fread(param, sizeof(char), 1024, param_file);
    if (!count) {
        ret = -1;
        goto CLEANUP;
    }
    fclose(param_file);
    pairing_init_set_buf(pairing, param, count);

    CLEANUP:
    return ret;
}

void AibeAlgo::init() {
    clear();

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

}

void AibeAlgo::server_setup() {
    element_random(g);
    element_random(mpk.h);
    element_random(mpk.Y);
    element_random(x);
    for (int i = 0; i < N; ++i) {
        element_random(mpk.Z[i]);
    }
    element_pow_zn(mpk.X, g, x);

}

// client keygen 1
void AibeAlgo::keygen1(const int id) {
    element_random(t0);
    element_random(theta);

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

    element_clear(r1);
    element_clear(t1);
    dk_clear(&dk);
    dk_clear(&dk1);

    element_clear(tz);
    element_clear(tg);
    element_clear(te);

}

