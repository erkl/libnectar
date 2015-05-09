#ifndef LIBNECTAR_25519_FE_H
#define LIBNECTAR_25519_FE_H

#include "include/nectar.h"

/* Namespacing. */
#define  fe             nectar__25519_fe_t

#define  fe_0           nectar__25519_fe_0
#define  fe_1           nectar__25519_fe_1
#define  fe_add         nectar__25519_fe_add
#define  fe_cmov        nectar__25519_fe_cmov
#define  fe_copy        nectar__25519_fe_copy
#define  fe_cswap       nectar__25519_fe_cswap
#define  fe_frombytes   nectar__25519_fe_frombytes
#define  fe_invert      nectar__25519_fe_invert
#define  fe_isnegative  nectar__25519_fe_isnegative
#define  fe_isnonzero   nectar__25519_fe_isnonzero
#define  fe_mul         nectar__25519_fe_mul
#define  fe_mul121666   nectar__25519_fe_mul121666
#define  fe_neg         nectar__25519_fe_neg
#define  fe_pow22523    nectar__25519_fe_pow22523
#define  fe_sq          nectar__25519_fe_sq
#define  fe_sq2         nectar__25519_fe_sq2
#define  fe_sub         nectar__25519_fe_sub
#define  fe_tobytes     nectar__25519_fe_tobytes

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
