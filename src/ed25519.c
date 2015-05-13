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
#include "src/25519/ge.h"
#include "src/25519/sc.h"


/* Generate a public key from a secret key. */
void nectar_ed25519_pubkey(uint8_t pk[32], const uint8_t sk[32]) {
    struct nectar_sha512_ctx h;
    uint8_t az[64];
    ge_p3 A;

    nectar_sha512_init(&h);
    nectar_sha512_update(&h, sk, 32);
    nectar_sha512_final(&h, az, 64);

    az[ 0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_scalarmult_base(&A, az);
    ge_p3_tobytes(pk, &A);
}


/* Sign a message. */
void nectar_ed25519_sign(uint8_t sign[64], const uint8_t *message, size_t len,
                         const uint8_t pk[32], const uint8_t sk[32]) {
    struct nectar_sha512_ctx h;
    uint8_t az[64];
    uint8_t nonce[64];
    uint8_t hram[64];
    ge_p3 R;

    nectar_sha512_init(&h);
    nectar_sha512_update(&h, sk, 32);
    nectar_sha512_final(&h, az, 64);

    az[ 0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    nectar_sha512_init(&h);
    nectar_sha512_update(&h, az + 32, 32);
    nectar_sha512_update(&h, message, len);
    nectar_sha512_final(&h, nonce, 64);

    sc_reduce(nonce);

    ge_scalarmult_base(&R, nonce);
    ge_p3_tobytes(sign, &R);

    nectar_sha512_init(&h);
    nectar_sha512_update(&h, sign, 32);
    nectar_sha512_update(&h, pk, 32);
    nectar_sha512_update(&h, message, len);
    nectar_sha512_final(&h, hram, 64);

    sc_reduce(hram);
    sc_muladd(sign + 32, hram, az, nonce);
}


/* Verify a message signature. */
int nectar_ed25519_verify(const uint8_t sign[64], const uint8_t *message, size_t len,
                          const uint8_t pk[32]) {
    struct nectar_sha512_ctx h;
    uint8_t hram[64];
    uint8_t tmp[32];
    ge_p3 A;
    ge_p2 R;

    if ((sign[63] & 0xe0) != 0)
        return -1;
    if (ge_frombytes_negate_vartime(&A, pk) != 0)
        return -1;

    nectar_sha512_init(&h);
    nectar_sha512_update(&h, sign, 32);
    nectar_sha512_update(&h, pk, 32);
    nectar_sha512_update(&h, message, len);
    nectar_sha512_final(&h, hram, 64);

    sc_reduce(hram);

    ge_double_scalarmult_vartime(&R, hram, &A, sign + 32);
    ge_tobytes(tmp, &R);

    return nectar_bcmp(tmp, sign, 32);
}
