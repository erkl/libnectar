#ifndef NECTAR_FE25519_H
#define NECTAR_FE25519_H

#include "nectar.h"

/* Namespacing. */
#define  fe             nectar_fe25519_t

#define  fe_0           nectar_fe25519_0
#define  fe_1           nectar_fe25519_1
#define  fe_add         nectar_fe25519_add
#define  fe_cmov        nectar_fe25519_cmov
#define  fe_copy        nectar_fe25519_copy
#define  fe_cswap       nectar_fe25519_cswap
#define  fe_frombytes   nectar_fe25519_frombytes
#define  fe_invert      nectar_fe25519_invert
#define  fe_isnegative  nectar_fe25519_isnegative
#define  fe_isnonzero   nectar_fe25519_isnonzero
#define  fe_mul         nectar_fe25519_mul
#define  fe_mul121666   nectar_fe25519_mul121666
#define  fe_neg         nectar_fe25519_neg
#define  fe_pow22523    nectar_fe25519_pow22523
#define  fe_sq          nectar_fe25519_sq
#define  fe_sq2         nectar_fe25519_sq2
#define  fe_sub         nectar_fe25519_sub
#define  fe_tobytes     nectar_fe25519_tobytes

/* Types. */
typedef int32_t fe[10];

/* Functions. */
void fe_0(fe h);
void fe_1(fe h);
void fe_add(fe h, const fe f, const fe g);
void fe_cmov(fe f, const fe g, unsigned int b);
void fe_copy(fe h, const fe f);
void fe_cswap(fe f, fe g, unsigned int b);
void fe_frombytes(fe h, const uint8_t * s);
void fe_invert(fe out, const fe z);
void fe_invert(fe out, const fe z);
int fe_isnegative(const fe f);
int fe_isnonzero(const fe f);
void fe_mul(fe h, const fe f, const fe g);
void fe_mul121666(fe h, const fe f);
void fe_neg(fe h, const fe f);
void fe_pow22523(fe out, const fe z);
void fe_sq(fe h, const fe f);
void fe_sq2(fe h, const fe f);
void fe_sub(fe h, const fe f, const fe g);
void fe_tobytes(uint8_t * s, const fe h);

#endif
