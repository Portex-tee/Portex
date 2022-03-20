
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