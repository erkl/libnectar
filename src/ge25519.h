#ifndef NECTAR_GE25519_H
#define NECTAR_GE25519_H

#include "nectar.h"
#include "fe25519.h"

/* Namespacing. */
#define  ge_p2                         nectar_ge25519_p2_t
#define  ge_p3                         nectar_ge25519_p3_t
#define  ge_p1p1                       nectar_ge25519_p1p1_t
#define  ge_precomp                    nectar_ge25519_precomp_t
#define  ge_cached                     nectar_ge25519_cached_t

#define  ge_add                        nectar_ge25519_add
#define  ge_double_scalarmult_vartime  nectar_ge25519_double_scalarmult_vartime
#define  ge_frombytes_negate_vartime   nectar_ge25519_frombytes_negate_vartime
#define  ge_madd                       nectar_ge25519_madd
#define  ge_msub                       nectar_ge25519_msub
#define  ge_p1p1_to_p2                 nectar_ge25519_p1p1_to_p2
#define  ge_p1p1_to_p3                 nectar_ge25519_p1p1_to_p3
#define  ge_p2_0                       nectar_ge25519_p2_0
#define  ge_p2_dbl                     nectar_ge25519_p2_dbl
#define  ge_p3_0                       nectar_ge25519_p3_0
#define  ge_p3_dbl                     nectar_ge25519_p3_dbl
#define  ge_p3_to_cached               nectar_ge25519_p3_to_cached
#define  ge_p3_to_p2                   nectar_ge25519_p3_to_p2
#define  ge_p3_tobytes                 nectar_ge25519_p3_tobytes
#define  ge_precomp_0                  nectar_ge25519_precomp_0
#define  ge_scalarmult_base            nectar_ge25519_scalarmult_base
#define  ge_sub                        nectar_ge25519_sub
#define  ge_tobytes                    nectar_ge25519_tobytes

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
