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

#ifndef LIBNECTAR_H
#define LIBNECTAR_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>


/* Implementation of the SHA-512 hash algorithm as defined in FIPS 180-2.
 *
 * The context object is initialized with `nectar_sha512_init`, and fed data
 * with `nectar_sha512_update`. Calling `nectar_sha512_final` generates the
 * final hash digest, at which point the context has to be re-initialized
 * before being used again. */
struct nectar_sha512_ctx {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buf[128];
};

void nectar_sha512_init(struct nectar_sha512_ctx * cx);
void nectar_sha512_update(struct nectar_sha512_ctx * cx, const uint8_t * data, size_t len);
void nectar_sha512_final(struct nectar_sha512_ctx * cx, uint8_t * digest, size_t len);


/* Implementation of the ChaCha20 stream cipher as defined in "ChaCha, a variant
 * of Salsa20" (Bernstein; 2008).
 *
 * After a context structure has been initialized with `nectar_chacha20_init`,
 * its keystream can be consumed using `nectar_chacha20_xor`, which XORs the
 * keystream with a supplied chunk of memory - either encrypting or decrypting
 * data. The context's keystream offset will be updated automatically.
 *
 * The `nectar_chacha20_seek` and `nectar_chacha20_tell` functions can be used
 * to either set or get the context's absolute position in the keystream. Note
 * that these functions deal with offsets measured in individual bytes, whereas
 * a "canonical" ChaCha20 implementation measures the stream offset in 64-byte
 * blocks. */
struct nectar_chacha20_ctx {
    uint32_t state[16];
    uint64_t offset;
};

void nectar_chacha20_init(struct nectar_chacha20_ctx * cx, const uint8_t key[32], const uint8_t iv[8]);
void nectar_chacha20_seek(struct nectar_chacha20_ctx * cx, uint64_t offset);
uint64_t nectar_chacha20_tell(struct nectar_chacha20_ctx * cx);
void nectar_chacha20_xor(struct nectar_chacha20_ctx * cx, uint8_t * dst, const uint8_t * src, size_t len);


/* Implementation of the Poly1305-AES Message Authentication Code (MAC)
 * algorithm.
 *
 * The context object is initialized with `nectar_poly1305_init`, and fed data
 * with `nectar_poly1305_update`. Calling `nectar_poly1305_final` generates the
 * final message authentication code, at which point the context has to be
 * re-initialized before being used again. */
struct nectar_poly1305_ctx {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buf[16];
    size_t rem;
};

void nectar_poly1305_init(struct nectar_poly1305_ctx * cx, const uint8_t key[32]);
void nectar_poly1305_update(struct nectar_poly1305_ctx * cx, uint8_t * data, size_t len);
void nectar_poly1305_final(struct nectar_poly1305_ctx * cx, uint8_t mac[16]);


/* Implementation of the Curve25519 elliptic curve Diffie-Hellman key agreement
 * scheme as defined in "Curve25519: new Diffie-Hellman speed records"
 * (Bernstein; 2006).
 *
 * Any sequence of 32 bytes can be re-shaped into a valid Curve25519 secret key
 * with the help of the `nectar_curve25519_clamp` function, and a corresponding
 * public key can be created using `nectar_curve25519_scalarmult_base`. The
 * `nectar_curve25519_scalarmult` function, given one party's private key and
 * the other's public key, calculates the shared secret. */
void nectar_curve25519_clamp(uint8_t priv[32]);
void nectar_curve25519_scalarmult_base(uint8_t pub[32], const uint8_t priv[32]);
void nectar_curve25519_scalarmult(uint8_t shared[32], const uint8_t priv[32], const uint8_t other_pub[32]);


/* Implementation of the Ed25519 digital signature scheme as defined in
 * "High-speed high-security signatures" (Bernstein, Duif, Lange, Schwabe,
 * Yang; 2011).
 *
 * The `nectar_ed25519_pubkey` function generates a valid Ed25519 public key
 * from any sequence of 32 bytes. This public key, together with the private
 * key, can then be used to generate a 64-byte signature for any chunk of data
 * using `nectar_ed25519_sign`. Signatures can be verified in constant time
 * with the `nectar_ed25519_verify` function. */
void nectar_ed25519_pubkey(uint8_t pub[32], const uint8_t priv[32]);
void nectar_ed25519_sign(uint8_t sign[64], const uint8_t * data, size_t len, const uint8_t pub[32], const uint8_t priv[32]);
int nectar_ed25519_verify(const uint8_t sign[64], const uint8_t * data, size_t len, const uint8_t pub[32]);


/* Implementation of the PBKDF2 key derivation function as defined in RFC 2898
 * and PKCS #5 v2.0, using SHA-512 rather than MD2, MD5 or SHA-1. */
void nectar_pbkdf2_sha512(uint8_t * key, size_t key_len,
                          const uint8_t * salt, size_t salt_len,
                          const uint8_t * pass, size_t pass_len,
                          unsigned int rounds);


/* Implementation of the SipHash-2-4 hash function as defined in "SipHash: a
 * fast short-input PRF" (Aumasson, Bernstein; 2012). */
uint64_t nectar_siphash(const uint8_t seed[16], const uint8_t * data, size_t len);


/* Utility function which compares two equally sized chunks of memory without
 * leaking any information via timing side channels. Returns 0 if and only if
 * the two chunks are identical. */
int nectar_bcmp(const uint8_t * buf0, const uint8_t * buf1, size_t len);


#endif
