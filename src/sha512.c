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


/* Round constants. */
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};


/* Padding material. */
static const uint8_t P[128] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


/* Core operations used by the `transform` function. */
#define ch(x,y,z)  ((x & (y^z)) ^ z)
#define maj(x,y,z) ((x & (y|z)) | (y&z))

#define rotr64(x,n) ((x >> n) | (x << (64-n)))

#define sum0(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define sum1(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define sig0(x) (rotr64(x,  1) ^ rotr64(x,  8) ^ (x >> 7))
#define sig1(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6))

#define rnd(t0,t1, a,b,c,d,e,f,g,h, x,k)                                       \
    t0 = h + sum1(e) + ch(e,f,g) + x + k;                                      \
    t1 = sum0(a) + maj(a,b,c);                                                 \
    d += t0;                                                                   \
    h = t0 + t1;


/* Apply the core SHA-512 transformation. */
static void transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t W[80];
    uint64_t A, B, C, D, E, F, G, H;
    uint64_t t0, t1;
    int i;

    /* Prepare W. */
    for (i = 0; i < 16; i++)
        W[i] = be64dec(&block[8*i]);
    for (i = 16; i < 80; i++)
        W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

    /* Initialize working state. */
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];

    /* Mix in 10 batches of 8. */
    for (i = 0; i < 80;) {
        rnd(t0, t1,  A, B, C, D, E, F, G, H,  W[i], K[i]);  i++;
        rnd(t0, t1,  H, A, B, C, D, E, F, G,  W[i], K[i]);  i++;
        rnd(t0, t1,  G, H, A, B, C, D, E, F,  W[i], K[i]);  i++;
        rnd(t0, t1,  F, G, H, A, B, C, D, E,  W[i], K[i]);  i++;
        rnd(t0, t1,  E, F, G, H, A, B, C, D,  W[i], K[i]);  i++;
        rnd(t0, t1,  D, E, F, G, H, A, B, C,  W[i], K[i]);  i++;
        rnd(t0, t1,  C, D, E, F, G, H, A, B,  W[i], K[i]);  i++;
        rnd(t0, t1,  B, C, D, E, F, G, H, A,  W[i], K[i]);  i++;
    }

    /* Update state. */
    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
    state[5] += F;
    state[6] += G;
    state[7] += H;
}


/* Initialize the SHA-512 context. */
void nectar_sha512_init(struct nectar_sha512_ctx * cx) {
    /* Initialization constants. */
    cx->state[0] = 0x6a09e667f3bcc908ULL;
    cx->state[1] = 0xbb67ae8584caa73bULL;
    cx->state[2] = 0x3c6ef372fe94f82bULL;
    cx->state[3] = 0xa54ff53a5f1d36f1ULL;
    cx->state[4] = 0x510e527fade682d1ULL;
    cx->state[5] = 0x9b05688c2b3e6c1fULL;
    cx->state[6] = 0x1f83d9abfb41bd6bULL;
    cx->state[7] = 0x5be0cd19137e2179ULL;

    cx->count[0] = 0;
    cx->count[1] = 0;
}


/* Write data to the SHA-512 context. */
void nectar_sha512_update(struct nectar_sha512_ctx * cx, const uint8_t * data, size_t len) {
    uint64_t t0, t1;
    uint64_t rem;

    /* Don't waste time if we have nothing to do. */
    if (len == 0)
        return;

    /* How much data is already waiting in the buffer? */
    rem = cx->count[1] % 128;

    /* Update the byte count. */
    t0 = (uint64_t) (len >> 32);
    t1 = (uint64_t) (len & 0xffffffff);

    cx->count[1] += t1;
    cx->count[0] += t0 + (cx->count[1] < t1 ? 1 : 0);

    if (rem > 0) {
        /* If we still don't have enough bytes for a full block, just buffer
         * the new input. */
        if (rem + len < 128) {
            memcpy(&cx->buf[rem], data, len);
            return;
        }

        /* Finish this block. */
        memcpy(&cx->buf[rem], data, 128 - rem);
        transform(cx->state, cx->buf);
        data += 128 - rem;
        len -= 128 - rem;
    }

    /* Transform full blocks, one at a time. */
    while (len >= 128) {
        transform(cx->state, data);
        data += 128;
        len -= 128;
    }

    /* Buffer any leftovers. */
    memcpy(cx->buf, data, len);
}


/* Write the SHA-512 digest to the output buffer. */
void nectar_sha512_final(struct nectar_sha512_ctx * cx, uint8_t * digest, size_t len) {
    uint8_t tmp[16];
    size_t rem, pad;
    size_t i, cutoff;

    /* Clamp the digest length. */
    if (len > 64)
        len = 64;

    /* Encode the bit count. */
    be64enc(&tmp[0], (cx->count[0] << 3) | (cx->count[1] >> 61));
    be64enc(&tmp[8], (cx->count[1] << 3));

    /* Mix in the padding, then the encoded bit count. */
    rem = (size_t) (cx->count[1] % 128);
    pad = (rem < 112 ? 112 - rem : 240 - rem);

    nectar_sha512_update(cx, P, pad);
    nectar_sha512_update(cx, tmp, 16);

    /* Copy the hash state into the digest buffer. The mask operation rounds
     * len down to the nearest multiple of 8. */
    cutoff = len & ~((size_t) (7));

    for (i = 0; i < cutoff; i += 8)
        be64enc(&digest[i], cx->state[i/8]);
    for (; i < len; i++)
        digest[i] = (uint8_t) (cx->state[i/8] >> (56 - 8*(i%8)));
}
