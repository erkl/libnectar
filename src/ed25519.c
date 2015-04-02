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
#include "25519/ge.h"
#include "25519/sc.h"


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
