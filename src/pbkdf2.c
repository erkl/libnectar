#include "nectar.h"
#include "endian.h"

/* HMAC-SHA-512 context structure. */
struct hmac_sha512_ctx {
    struct sha512_ctx inner;
    struct sha512_ctx outer;
};

/* Initialize a HMAC-SHA-512 context structure. */
static void hmac_sha512_init(struct hmac_sha512_ctx * cx,
                             const uint8_t * key, size_t len) {
    uint8_t pad[128];
    uint8_t khash[64];
    size_t i;

    /* Shrink long keys. */
    if (len > 128) {
        sha512_init(&cx->inner);
        sha512_update(&cx->inner, key, len);
        sha512_final(&cx->inner, khash, 64);

        key = khash;
        len = 64;
    }

    /* Initialize the inner hash context. */
    for (i = 0; i < len; i++)
        pad[i] = 0x36 ^ key[i];
    for (i = len; i < 128; i++)
        pad[i] = 0x36;

    sha512_init(&cx->inner);
    sha512_update(&cx->inner, pad, 128);

    /* Initialize the outer hash context. */
    for (i = 0; i < len; i++)
        pad[i] = 0x5c ^ key[i];
    for (i = len; i < 128; i++)
        pad[i] = 0x5c;

    sha512_init(&cx->outer);
    sha512_update(&cx->outer, pad, 128);
}

/* Feed input data into a context. */
static inline void hmac_sha512_update(struct hmac_sha512_ctx * cx,
                                      const uint8_t * data, size_t len) {
    sha512_update(&cx->inner, data, len);
}

/* Output the final HMAC digest. */
static void hmac_sha512_final(struct hmac_sha512_ctx * cx,
                              uint8_t * digest, size_t len) {
    uint8_t inner[64];

    sha512_final(&cx->inner, inner, 64);
    sha512_update(&cx->outer, inner, 64);
    sha512_final(&cx->outer, digest, len);
}

/* Duplicate a HMAC context. */
static void hmac_sha512_copy(struct hmac_sha512_ctx * dst, struct hmac_sha512_ctx * src) {
    memcpy(dst, src, sizeof(*dst));
}

/* Derive a stronger password. */
void pbkdf2_sha512(uint8_t * key, size_t key_len,
                   const uint8_t * salt, size_t salt_len,
                   const uint8_t * pass, size_t pass_len,
                   unsigned int rounds) {
    struct hmac_sha512_ctx h0, h1;
    uint8_t tmp[64];
    unsigned int i, j;
    uint32_t count;
    size_t num;

    /* Create one initialized HMAC context that we copy for each round. */
    hmac_sha512_init(&h1, pass, pass_len);

    /* Generate the key, 64 bytes at a time. */
    count = 1;

    while (key_len > 0) {
        num = (key_len > 64 ? 64 : key_len);

        /* Perform the first round. */
        le32enc(tmp, count++);

        hmac_sha512_copy(&h0, &h1);
        hmac_sha512_update(&h0, salt, salt_len);
        hmac_sha512_update(&h0, tmp, 4);
        hmac_sha512_final(&h0, key, num);

        /* ...and then all subsequent rounds. */
        for (i = 1; i < rounds; i++) {
            hmac_sha512_copy(&h0, &h1);
            hmac_sha512_update(&h0, tmp, 64);
            hmac_sha512_final(&h0, tmp, 64);

            /* Mix the latest digest with the accumulated output. */
            for (j = 0; j < num; j++)
                key[j] ^= tmp[j];
        }

        key += num;
        key_len -= num;
    }
}
