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


/* Initialize an HMAC-SHA-512 context structure. */
void nectar_hmac_sha512_init(struct nectar_hmac_sha512_ctx * cx,
                             const uint8_t * key, size_t len) {
    uint8_t pad[128];
    uint8_t khash[64];
    size_t i;

    /* Shrink long keys. */
    if (len > 128) {
        nectar_sha512_init(&cx->inner);
        nectar_sha512_update(&cx->inner, key, len);
        nectar_sha512_final(&cx->inner, khash, 64);

        key = khash;
        len = 64;
    }

    /* Initialize the inner hash context. */
    for (i = 0; i < len; i++)
        pad[i] = 0x36 ^ key[i];
    for (i = len; i < 128; i++)
        pad[i] = 0x36;

    nectar_sha512_init(&cx->inner);
    nectar_sha512_update(&cx->inner, pad, 128);

    /* Initialize the outer hash context. */
    for (i = 0; i < len; i++)
        pad[i] = 0x5c ^ key[i];
    for (i = len; i < 128; i++)
        pad[i] = 0x5c;

    nectar_sha512_init(&cx->outer);
    nectar_sha512_update(&cx->outer, pad, 128);
}


/* Feed input data into an HMAC-SHA-512 context. */
void nectar_hmac_sha512_update(struct nectar_hmac_sha512_ctx * cx,
                               const uint8_t * data, size_t len) {
    nectar_sha512_update(&cx->inner, data, len);
}


/* Output the MAC. */
void nectar_hmac_sha512_final(struct nectar_hmac_sha512_ctx * cx,
                              uint8_t * digest, size_t len) {
    uint8_t inner[64];

    nectar_sha512_final(&cx->inner, inner, 64);
    nectar_sha512_update(&cx->outer, inner, 64);
    nectar_sha512_final(&cx->outer, digest, len);
}
