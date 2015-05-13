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


/* Derive a stronger password. */
void nectar_pbkdf2_sha512(uint8_t * key, size_t key_len,
                          const uint8_t * salt, size_t salt_len,
                          const uint8_t * pass, size_t pass_len,
                          unsigned long rounds) {
    struct nectar_hmac_sha512_ctx h0, h1;
    uint8_t tmp[64];
    unsigned long i, j;
    uint32_t count;
    size_t num;

    /* Create one initialized HMAC context that we copy for each round. */
    nectar_hmac_sha512_init(&h1, pass, pass_len);

    /* Generate the key, 64 bytes at a time. */
    count = 1;

    while (key_len > 0) {
        num = (key_len > 64 ? 64 : key_len);

        /* Perform the first round. */
        le32enc(tmp, count++);

        memcpy(&h0, &h1, sizeof(struct nectar_hmac_sha512_ctx));
        nectar_hmac_sha512_update(&h0, salt, salt_len);
        nectar_hmac_sha512_update(&h0, tmp, 4);
        nectar_hmac_sha512_final(&h0, key, num);

        /* ...and then all subsequent rounds. */
        for (i = 1; i < rounds; i++) {
            memcpy(&h0, &h1, sizeof(struct nectar_hmac_sha512_ctx));
            nectar_hmac_sha512_update(&h0, tmp, 64);
            nectar_hmac_sha512_final(&h0, tmp, 64);

            /* Mix the latest digest with the accumulated output. */
            for (j = 0; j < num; j++)
                key[j] ^= tmp[j];
        }

        key += num;
        key_len -= num;
    }
}
