#ifndef NECTAR_H
#define NECTAR_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Implementation of the SHA-512 hash algorithm as defined in FIPS 180-2.
 *
 * The context object is initialized with `sha512_init`, and fed data with
 * `sha512_update`. Calling `sha512_final` generates the final hash digest,
 * at which point the context has to be re-initialized before being used
 * again. */
struct sha512_ctx {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buf[128];
};

void sha512_init(struct sha512_ctx * cx);
void sha512_update(struct sha512_ctx * cx, const uint8_t * data, size_t len);
void sha512_final(struct sha512_ctx * cx, uint8_t * digest, size_t len);

/* Implementation of the ChaCha20 stream cipher as defined in "ChaCha, a variant
 * of Salsa20" (Bernstein; 2008).
 *
 * After a context structure has been initialized with `chacha20_init`, its
 * keystream can be consumed using `chacha20_xor`, which XORs the keystream
 * with a supplied chunk of memory, to encrypt or decrypt data. The context's
 * keystream offset will be updated automatically.
 *
 * The `chacha20_seek` and `chacha20_tell` functions can be used to either set
 * or get the context's absolute position in the keystream. Note that these
 * functions deal with offsets measured in individual bytes, whereas a
 * "canonical" ChaCha20 implementation measures the stream offset in 64-byte
 * blocks. */
struct chacha20_ctx {
    uint32_t state[16];
    uint64_t offset;
};

void chacha20_init(struct chacha20_ctx * cx, const uint8_t key[32], const uint8_t iv[8]);
void chacha20_seek(struct chacha20_ctx * cx, uint64_t offset);
uint64_t chacha20_tell(struct chacha20_ctx * cx);
void chacha20_xor(struct chacha20_ctx * cx, uint8_t * dst, const uint8_t * src, size_t len);

/* Implementation of the Poly1305-AES Message Authentication Code (MAC)
 * algorithm.
 *
 * The context object is initialized with `poly1305_init`, and fed data with
 * `poly1305_update`. Calling `poly1305_final` generates the final message
 * authentication code, at which point the context has to be re-initialized
 * before being used again. */
struct poly1305_ctx {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buf[16];
    size_t rem;
};

void poly1305_init(struct poly1305_ctx * cx, const uint8_t key[32]);
void poly1305_update(struct poly1305_ctx * cx, uint8_t * data, size_t len);
void poly1305_final(struct poly1305_ctx * cx, uint8_t mac[16]);

/* Implementation of the PBKDF2 key derivation function as defined in RFC 2898
 * and PKCS #5 v2.0, using SHA-512 rather than MD2, MD5 or SHA-1. */
void pbkdf2_sha512(uint8_t * key, size_t key_len,
                   const uint8_t * salt, size_t salt_len,
                   const uint8_t * pass, size_t pass_len,
                   unsigned int rounds);

/* Utility function which compares two equally sized chunks of memory without
 * leaking any information via timing side channels. Returns 0 if and only if
 * the two chunks are identical. */
int safe_bcmp(const uint8_t * buf0, const uint8_t * buf1, size_t len);

#endif
