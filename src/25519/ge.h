#ifndef NECTAR_25519_GE_H
#define NECTAR_25519_GE_H

#include "nectar.h"
#include "fe.h"

/* Namespacing. */
#define  ge_p2                         nectar__25519_ge_p2_t
#define  ge_p3                         nectar__25519_ge_p3_t
#define  ge_p1p1                       nectar__25519_ge_p1p1_t
#define  ge_precomp                    nectar__25519_ge_precomp_t
#define  ge_cached                     nectar__25519_ge_cached_t

#define  ge_add                        nectar__25519_ge_add
#define  ge_double_scalarmult_vartime  nectar__25519_ge_double_scalarmult_vartime
#define  ge_frombytes_negate_vartime   nectar__25519_ge_frombytes_negate_vartime
#define  ge_madd                       nectar__25519_ge_madd
#define  ge_msub                       nectar__25519_ge_msub
#define  ge_p1p1_to_p2                 nectar__25519_ge_p1p1_to_p2
#define  ge_p1p1_to_p3                 nectar__25519_ge_p1p1_to_p3
#define  ge_p2_0                       nectar__25519_ge_p2_0
#define  ge_p2_dbl                     nectar__25519_ge_p2_dbl
#define  ge_p3_0                       nectar__25519_ge_p3_0
#define  ge_p3_dbl                     nectar__25519_ge_p3_dbl
#define  ge_p3_to_cached               nectar__25519_ge_p3_to_cached
#define  ge_p3_to_p2                   nectar__25519_ge_p3_to_p2
#define  ge_p3_tobytes                 nectar__25519_ge_p3_tobytes
#define  ge_precomp_0                  nectar__25519_ge_precomp_0
#define  ge_scalarmult_base            nectar__25519_ge_scalarmult_base
#define  ge_sub                        nectar__25519_ge_sub
#define  ge_tobytes                    nectar__25519_ge_tobytes

/* Types. */
typedef struct { fe X, Y, Z; } ge_p2;
typedef struct { fe X, Y, Z, T; } ge_p3;
typedef struct { fe X, Y, Z, T; } ge_p1p1;
typedef struct { fe yplusx, yminusx, xy2d; } ge_precomp;
typedef struct { fe YplusX, YminusX, Z, T2d; } ge_cached;

/* Functions. */
void ge_add(ge_p1p1 * r, const ge_p3 * p, const ge_cached * q);
void ge_double_scalarmult_vartime(ge_p2 * r, const uint8_t * a, const ge_p3 * A, const uint8_t * b);
int ge_frombytes_negate_vartime(ge_p3 * h, const uint8_t * s);
void ge_madd(ge_p1p1 * r, const ge_p3 * p, const ge_precomp * q);
void ge_msub(ge_p1p1 * r, const ge_p3 * p, const ge_precomp * q);
void ge_p1p1_to_p2(ge_p2 * r, const ge_p1p1 * p);
void ge_p1p1_to_p3(ge_p3 * r, const ge_p1p1 * p);
void ge_p2_0(ge_p2 * h);
void ge_p2_dbl(ge_p1p1 * r, const ge_p2 * p);
void ge_p3_0(ge_p3 * h);
void ge_p3_dbl(ge_p1p1 * r, const ge_p3 * p);
void ge_p3_to_cached(ge_cached * r, const ge_p3 * p);
void ge_p3_to_p2(ge_p2 * r, const ge_p3 * p);
void ge_p3_tobytes(uint8_t * s, const ge_p3 * h);
void ge_precomp_0(ge_precomp * h);
void ge_scalarmult_base(ge_p3 * h, const uint8_t * a);
void ge_sub(ge_p1p1 * r, const ge_p3 * p, const ge_cached * q);
void ge_tobytes(uint8_t * s, const ge_p2 * h);

#endif
