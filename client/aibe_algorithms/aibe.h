//
// Created by jojjiw on 2022/3/17.
//

#ifndef PBC_TEST_AIBE_H
#define PBC_TEST_AIBE_H

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>

#define N 8
const int z_size = N + 1;
const int ID = 0b10101010;
const char file_path[] = "param/aibe.param";


typedef struct mpk_t {
    element_t X, Y, h, Z[N + 1];
} mpk_t;


typedef struct dk_t {
    element_t d1, d2, d3;

} dk_t;

void mpk_init(mpk_t *mpk, pairing_t pairing);

void mpk_clear(mpk_t *mpk);

void dk_init(dk_t *dk, pairing_t pairing);

void dk_clear(dk_t *dk);

int get_bit(int id, int n);

class AibeAlgo {
public:
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

    pairing_t pairing;

    AibeAlgo(){};

    int run(FILE *OUTPUT);

    int load_param(const char *fn);

    void server_setup();

    void init();

    void keygen1(int id);

    void keygen2();

    int keygen3();

    void clear();

};


#endif //PBC_TEST_AIBE_H
