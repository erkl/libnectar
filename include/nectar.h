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

#endif
