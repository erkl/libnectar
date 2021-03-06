/* Copyright (c) 2015, Erik Lundin.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE. */

#include "include/nectar.h"
#include "src/25519/fe.h"


/* Basepoint. */
static const uint8_t basepoint[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


/* Massage a 32-byte seed into a valid Curve25519 secret. */
void nectar_curve25519_clamp(uint8_t priv[32]) {
    priv[ 0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
}


/* Multiply n with the basepoint and store the result in q. */
void nectar_curve25519_scalarmult_base(uint8_t q[32], const uint8_t n[32]) {
    nectar_curve25519_scalarmult(q, n, basepoint);
}


/* Multiply p and n, storing the result in q. */
void nectar_curve25519_scalarmult(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]) {
    uint8_t e[32];
    unsigned int b, s = 0;
    fe x1, x2, z2, x3, z3;
    fe t0, t1;
    int pos;

    memcpy(e, n, 32);

    fe_frombytes(x1, p);
    fe_1(x2);
    fe_copy(x3, x1);
    fe_0(z2);
    fe_1(z3);

    for (pos = 254; pos >= 0; pos--) {
        b = (e[pos/8] >> (pos&7)) & 1;

        s ^= b;
        fe_cswap(x2, x3, s);
        fe_cswap(z2, z3, s);
        s = b;

        fe_sub(t0, x3, z3);
        fe_sub(t1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, t0, x2);
        fe_mul(z2, z2, t1);
        fe_sq(t0, t1);
        fe_sq(t1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, t1, t0);
        fe_sub(t1, t1, t0);
        fe_sq(z2, z2);
        fe_mul121666(z3, t1);
        fe_sq(x3, x3);
        fe_add(t0, t0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, t1, t0);
    }

    fe_cswap(x2, x3, s);
    fe_cswap(z2, z3, s);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);
}
