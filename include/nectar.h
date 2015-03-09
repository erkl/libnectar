#ifndef LIBNECTAR_H
#define LIBNECTAR_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Namespacing. */
#define  sha512_ctx                  nectar__sha512_ctx
#define  sha512_init                 nectar__sha512_init
#define  sha512_update               nectar__sha512_update
#define  sha512_final                nectar__sha512_final
#define  chacha20_ctx                nectar__chacha20_ctx
#define  chacha20_init               nectar__chacha20_init
#define  chacha20_seek               nectar__chacha20_seek
#define  chacha20_tell               nectar__chacha20_tell
#define  chacha20_xor                nectar__chacha20_xor
#define  poly1305_ctx                nectar__poly1305_ctx
#define  poly1305_init               nectar__poly1305_init
#define  poly1305_update             nectar__poly1305_update
#define  poly1305_final              nectar__poly1305_final
#define  curve25519_clamp            nectar__curve25519_clamp
#define  curve25519_scalarmult_base  nectar__curve25519_scalarmult_base
#define  curve25519_scalarmult       nectar__curve25519_scalarmult
#define  ed25519_pubkey              nectar__ed25519_pubkey
#define  ed25519_sign                nectar__ed25519_sign
#define  ed25519_verify              nectar__ed25519_verify
#define  pbkdf2_sha512               nectar__pbkdf2_sha512
#define  safe_bcmp                   nectar__safe_bcmp

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

/* Implementation of the Curve25519 elliptic curve Diffie-Hellman key agreement
 * scheme as defined in "Curve25519: new Diffie-Hellman speed records"
 * (Bernstein; 2006).
 *
 * Any sequence of 32 bytes can be re-shaped into a valid Curve25519 secret
 * key with the help of the `curve25519_clamp` function, and a corresponding
 * public key can be created using `curve25519_scalarmult_base`. The
 * `curve25519_scalarmult` function, given one party's private key and the
 * other's public key, calculates the shared secret. */
void curve25519_clamp(uint8_t priv[32]);
void curve25519_scalarmult_base(uint8_t pub[32], const uint8_t priv[32]);
void curve25519_scalarmult(uint8_t shared[32], const uint8_t priv[32], const uint8_t other_pub[32]);

/* Implementation of the Ed25519 digital signature scheme as defined in
 * "High-speed high-security signatures" (Bernstein, Duif, Lange, Schwabe,
 * Yang; 2011).
 *
 * The `ed25519_pubkey` function generates a valid Ed25519 public key from any
 * sequence of 32 bytes. This public key, together with the private key, can
 * then be used to generate a 64-byte signature for any chunk of data using
 * `ed25519_sign`. Signatures can be verified in constant time with the
 * `ed25519_verify` function. */
void ed25519_pubkey(uint8_t pub[32], const uint8_t priv[32]);
void ed25519_sign(uint8_t sign[64], const uint8_t * data, size_t len, const uint8_t pub[32], const uint8_t priv[32]);
int ed25519_verify(const uint8_t sign[64], const uint8_t * data, size_t len, const uint8_t pub[32]);

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
