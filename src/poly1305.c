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


/* Padding material. */
static const uint8_t P[16] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/* Inner block processing algorithm. */
static size_t blocks(struct nectar_poly1305_ctx * cx,
                     uint8_t * data, size_t len, int final) {
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;

    const uint32_t hibit = (final ? 0 : 1<<24);
    size_t total = len;

    /* Load state into local working variables. */
    r0 = cx->r[0];
    r1 = cx->r[1];
    r2 = cx->r[2];
    r3 = cx->r[3];
    r4 = cx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = cx->h[0];
    h1 = cx->h[1];
    h2 = cx->h[2];
    h3 = cx->h[3];
    h4 = cx->h[4];

    /* Process the input in chunks of 16 bytes. */
    do {
        h0 += (le32dec(data +  0))      & 0x3ffffff;
        h1 += (le32dec(data +  3) >> 2) & 0x3ffffff;
        h2 += (le32dec(data +  6) >> 4) & 0x3ffffff;
        h3 += (le32dec(data +  9) >> 6) & 0x3ffffff;
        h4 += (le32dec(data + 12) >> 8) | hibit;

        d0 = ((uint64_t) h0 * r0) + ((uint64_t) h1 * s4) + ((uint64_t) h2 * s3) + ((uint64_t) h3 * s2) + ((uint64_t) h4 * s1);
        d1 = ((uint64_t) h0 * r1) + ((uint64_t) h1 * r0) + ((uint64_t) h2 * s4) + ((uint64_t) h3 * s3) + ((uint64_t) h4 * s2);
        d2 = ((uint64_t) h0 * r2) + ((uint64_t) h1 * r1) + ((uint64_t) h2 * r0) + ((uint64_t) h3 * s4) + ((uint64_t) h4 * s3);
        d3 = ((uint64_t) h0 * r3) + ((uint64_t) h1 * r2) + ((uint64_t) h2 * r1) + ((uint64_t) h3 * r0) + ((uint64_t) h4 * s4);
        d4 = ((uint64_t) h0 * r4) + ((uint64_t) h1 * r3) + ((uint64_t) h2 * r2) + ((uint64_t) h3 * r1) + ((uint64_t) h4 * r0);

        c = (uint32_t) (d0 >> 26);  h0 = (uint32_t) d0 & 0x3ffffff;  d1 += c;
        c = (uint32_t) (d1 >> 26);  h1 = (uint32_t) d1 & 0x3ffffff;  d2 += c;
        c = (uint32_t) (d2 >> 26);  h2 = (uint32_t) d2 & 0x3ffffff;  d3 += c;
        c = (uint32_t) (d3 >> 26);  h3 = (uint32_t) d3 & 0x3ffffff;  d4 += c;
        c = (uint32_t) (d4 >> 26);  h4 = (uint32_t) d4 & 0x3ffffff;  h0 += c * 5;
        c =            (h0 >> 26);  h0 =            h0 & 0x3ffffff;  h1 += c;

        data += 16;
        len -= 16;
    } while (len >= 16);

    /* Store the new state. */
    cx->h[0] = h0;
    cx->h[1] = h1;
    cx->h[2] = h2;
    cx->h[3] = h3;
    cx->h[4] = h4;

    /* How many bytes did we consume? */
    return total - len;
}


/* Initialize the context structure. */
void nectar_poly1305_init(struct nectar_poly1305_ctx * cx, const uint8_t key[32]) {
    /* Initialize r and h. */
    cx->r[0] = (le32dec(&key[ 0])     ) & 0x3ffffff;
    cx->r[1] = (le32dec(&key[ 3]) >> 2) & 0x3ffff03;
    cx->r[2] = (le32dec(&key[ 6]) >> 4) & 0x3ffc0ff;
    cx->r[3] = (le32dec(&key[ 9]) >> 6) & 0x3f03fff;
    cx->r[4] = (le32dec(&key[12]) >> 8) & 0x00fffff;

    cx->h[0] = 0;
    cx->h[1] = 0;
    cx->h[2] = 0;
    cx->h[3] = 0;
    cx->h[4] = 0;

    /* Store pad for later use. */
    cx->pad[0] = le32dec(&key[16]);
    cx->pad[1] = le32dec(&key[20]);
    cx->pad[2] = le32dec(&key[24]);
    cx->pad[3] = le32dec(&key[28]);

    /* The buffer obviously starts out empty. */
    cx->rem = 0;
}


/* Feed the context more data. */
void nectar_poly1305_update(struct nectar_poly1305_ctx * cx, uint8_t * data, size_t len) {
    size_t n;

    /* Ignore empty input. */
    if (len == 0)
        return;

    /* Be sure we use any data already in the buffer. */
    if (cx->rem > 0) {
        n = 16 - cx->rem;

        /* If we don't have enough input to fill the buffer now, add
         * everything we have and exit early. */
        if (len < n) {
            memcpy(&cx->buf[cx->rem], data, len);
            cx->rem += len;
            return;
        }

        /* Fill the buffer and process it. */
        memcpy(&cx->buf[cx->rem], data, n);
        cx->rem = 0;

        blocks(cx, cx->buf, 16, 0);
        data += n;
        len -= n;
    }

    /* Process as many chunks of 16 bytes as possible. */
    if (len >= 16) {
        n = blocks(cx, data, len, 0);
        data += n;
        len -= n;
    }

    /* Buffer any leftovers. */
    if (len > 0) {
        memcpy(&cx->buf[cx->rem], data, len);
        cx->rem += len;
    }
}


/* Generate the final message authentication code. */
void nectar_poly1305_final(struct nectar_poly1305_ctx * cx, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t f;
    uint32_t mask;

    /* If there is still some data left in the buffer, fill the remaining
     * space with padding and process one last block. */
    if (cx->rem > 0) {
        memcpy(&cx->buf[cx->rem], P, 16 - cx->rem);
        blocks(cx, cx->buf, 16, 1);
    }

    h0 = cx->h[0];
    h1 = cx->h[1];
    h2 = cx->h[2];
    h3 = cx->h[3];
    h4 = cx->h[4];

    c = h1 >> 26;  h1 = h1 & 0x3ffffff;  h2 += c;
    c = h2 >> 26;  h2 = h2 & 0x3ffffff;  h3 += c;
    c = h3 >> 26;  h3 = h3 & 0x3ffffff;  h4 += c;
    c = h4 >> 26;  h4 = h4 & 0x3ffffff;  h0 += c * 5;
    c = h0 >> 26;  h0 = h0 & 0x3ffffff;  h1 += c;

    g0 = h0 + 5;  c = g0 >> 26;  g0 &= 0x3ffffff;
    g1 = h1 + c;  c = g1 >> 26;  g1 &= 0x3ffffff;
    g2 = h2 + c;  c = g2 >> 26;  g2 &= 0x3ffffff;
    g3 = h3 + c;  c = g3 >> 26;  g3 &= 0x3ffffff;
    g4 = h4 + c - (1 << 26);

    mask = (g4 >> (32-1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;

    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    f = (uint64_t) h0 + cx->pad[0];              h0 = (uint32_t) f;
    f = (uint64_t) h1 + cx->pad[1] + (f >> 32);  h1 = (uint32_t) f;
    f = (uint64_t) h2 + cx->pad[2] + (f >> 32);  h2 = (uint32_t) f;
    f = (uint64_t) h3 + cx->pad[3] + (f >> 32);  h3 = (uint32_t) f;

    /* Write the now calculated MAC. */
    le32enc(&mac[ 0], h0);
    le32enc(&mac[ 4], h1);
    le32enc(&mac[ 8], h2);
    le32enc(&mac[12], h3);
}
