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
#include "src/endian.h"


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
