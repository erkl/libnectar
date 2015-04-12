/* Copyright (c) 2015, Erik Lundin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   3. Neither the name of the copyright holder nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.
 *
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

#include "nectar.h"
#include "endian.h"


/* Support macros. */
#define rotl64(x, n)                                                           \
    ((uint64_t) (((x) << (n)) | ((x) >> (64 - (n)))))

#define rnd(v0, v1, v2, v3)                                                    \
    do {                                                                       \
        v0 += v1;  v1 = rotl64(v1, 13);  v1 ^= v0;  v0 = rotl64(v0, 32);       \
        v2 += v3;  v3 = rotl64(v3, 16);  v3 ^= v2;                             \
        v0 += v3;  v3 = rotl64(v3, 21);  v3 ^= v0;                             \
        v2 += v1;  v1 = rotl64(v1, 17);  v1 ^= v2;  v2 = rotl64(v2, 32);       \
    } while (0)


/* Implementation of the SipHash-2-4 hash function as defined in "SipHash: a
 * fast short-input PRF" (Aumasson, Bernstein; 2012). */
uint64_t nectar_siphash(const uint8_t seed[16], const uint8_t * data, size_t len) {
    uint64_t k0, k1;
    uint64_t v0, v1, v2, v3;
    uint64_t m;
    const uint8_t * end;
    size_t rem;

    /* Initialize state. */
    k0 = le64dec(seed);
    k1 = le64dec(seed + 8);

    v0 = be64dec((const uint8_t *) "somepseu") ^ k0;
    v1 = be64dec((const uint8_t *) "dorandom") ^ k1;
    v2 = be64dec((const uint8_t *) "lygenera") ^ k0;
    v3 = be64dec((const uint8_t *) "tedbytes") ^ k1;

    /* Split the input into 64-bit blocks and mix them into the hash state,
     * one by one. */
    rem = len & 7;
    end = data + (len - rem);

    while (data < end) {
        m = le64dec(data);

        v3 ^= m;
        rnd(v0, v1, v2, v3);
        rnd(v0, v1, v2, v3);
        v0 ^= m;

        data += 8;
    }

    /* Mix in the `len` argument's lower bits, together with any bytes
     * remaining of the input. */
    m = ((uint64_t) len) << 56;

    switch (rem) {
    case 7: m |= ((uint64_t) data[6]) << 48;
    case 6: m |= ((uint64_t) data[5]) << 40;
    case 5: m |= ((uint64_t) data[4]) << 32;
    case 4: m |= ((uint64_t) data[3]) << 24;
    case 3: m |= ((uint64_t) data[2]) << 16;
    case 2: m |= ((uint64_t) data[1]) << 8;
    case 1: m |= ((uint64_t) data[0]);
    }

    v3 ^= m;
    rnd(v0, v1, v2, v3);
    rnd(v0, v1, v2, v3);
    v0 ^= m;

    /* Finalize the hash. */
    v2 ^= 0xff;
    rnd(v0, v1, v2, v3);
    rnd(v0, v1, v2, v3);
    rnd(v0, v1, v2, v3);
    rnd(v0, v1, v2, v3);

    /* Reduce the hash state to a 64-bit digest. */
    m = v0 ^ v1 ^ v2 ^ v3;

    return le64dec((const uint8_t *) &m);
}
