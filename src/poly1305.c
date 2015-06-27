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


/* Padding material. */
static const uint8_t P[16] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


/* Support macros. */
#define out(dst, h0, h1, h2, h3)                                               \
    do {                                                                       \
        le32enc(&((dst)[ 0]), h0);                                             \
        le32enc(&((dst)[ 4]), h1);                                             \
        le32enc(&((dst)[ 8]), h2);                                             \
        le32enc(&((dst)[12]), h3);                                             \
    } while (0)


/* Inner block processing algorithm. */
static size_t blocks(struct nectar_poly1305_ctx * cx,
                     const uint8_t * data, size_t len, int final) {
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
        h0 += (le32dec(data +  0)     ) & 0x3ffffff;
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
    /* r = key & 0x00ffffffc0ffffffc0ffffffc0fffffff. */
    cx->r[0] = (le32dec(&key[ 0])     ) & 0x3ffffff;
    cx->r[1] = (le32dec(&key[ 3]) >> 2) & 0x3ffff03;
    cx->r[2] = (le32dec(&key[ 6]) >> 4) & 0x3ffc0ff;
    cx->r[3] = (le32dec(&key[ 9]) >> 6) & 0x3f03fff;
    cx->r[4] = (le32dec(&key[12]) >> 8) & 0x00fffff;

    /* h = 0. */
    cx->h[0] = 0;
    cx->h[1] = 0;
    cx->h[2] = 0;
    cx->h[3] = 0;
    cx->h[4] = 0;

    /* pad = key >> 128. */
    cx->pad[0] = le32dec(&key[16]);
    cx->pad[1] = le32dec(&key[20]);
    cx->pad[2] = le32dec(&key[24]);
    cx->pad[3] = le32dec(&key[28]);

    /* The buffer obviously starts out empty. */
    cx->rem = 0;
}


/* Feed the context more data. */
void nectar_poly1305_update(struct nectar_poly1305_ctx * cx, const uint8_t * data, size_t len) {
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
void nectar_poly1305_final(struct nectar_poly1305_ctx * cx, uint8_t * mac, size_t len) {
    uint32_t h0, h1, h2, h3, h4, c;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t mask;
    uint64_t f;
    uint8_t tmp[16];

    /* If there is still some data left in the buffer, fill the remaining
     * space with padding and process one last block. */
    if (cx->rem > 0) {
        memcpy(&cx->buf[cx->rem], P, 16 - cx->rem);
        blocks(cx, cx->buf, 16, 1);
    }

    /* Load state. */
    h0 = cx->h[0];
    h1 = cx->h[1];
    h2 = cx->h[2];
    h3 = cx->h[3];
    h4 = cx->h[4];

    /* Let's use the next 30 lines or so to make some pretty patterns on
     * the reader's screen. */
    c = h1 >> 26;  h1 &= 0x3ffffff;  h2 += c;
    c = h2 >> 26;  h2 &= 0x3ffffff;  h3 += c;
    c = h3 >> 26;  h3 &= 0x3ffffff;  h4 += c;
    c = h4 >> 26;  h4 &= 0x3ffffff;  h0 += c * 5;
    c = h0 >> 26;  h0 &= 0x3ffffff;  h1 += c;

    g0 = h0 + 5;  c = g0 >> 26;  g0 &= 0x3ffffff;
    g1 = h1 + c;  c = g1 >> 26;  g1 &= 0x3ffffff;
    g2 = h2 + c;  c = g2 >> 26;  g2 &= 0x3ffffff;
    g3 = h3 + c;  c = g3 >> 26;  g3 &= 0x3ffffff;
    g4 = h4 + c - (1 << 26);

    mask = (g4 >> 31) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;

    mask = ~mask;
    h0 &= mask;  h0 |= g0;
    h1 &= mask;  h1 |= g1;
    h2 &= mask;  h2 |= g2;
    h3 &= mask;  h3 |= g3;
    h4 &= mask;  h4 |= g4;

    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* Mix in `pad`. */
    f = (uint64_t) h0 + cx->pad[0];              h0 = (uint32_t) f;
    f = (uint64_t) h1 + cx->pad[1] + (f >> 32);  h1 = (uint32_t) f;
    f = (uint64_t) h2 + cx->pad[2] + (f >> 32);  h2 = (uint32_t) f;
    f = (uint64_t) h3 + cx->pad[3] + (f >> 32);  h3 = (uint32_t) f;

    /* Use a temporary buffer if there isn't room for the full MAC. */
    if (len >= 16) {
        out(mac, h0, h1, h2, h3);
    } else {
        out(tmp, h0, h1, h2, h3);
        memcpy(mac, tmp, len);
    }
}
