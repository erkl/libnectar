#include "nectar.h"
#include "endian.h"

/* Core operations. */
#define rotl32(v, n)                                                           \
    (((v) << (n)) | ((v) >> (32 - (n))))

#define qtr(t, x, a,b,c,d)                                                     \
    do {                                                                       \
        x[a] += x[b];  t = x[d] ^ x[a];  x[d] = rotl32(t, 16);                 \
        x[c] += x[d];  t = x[b] ^ x[c];  x[b] = rotl32(t, 12);                 \
        x[a] += x[b];  t = x[d] ^ x[a];  x[d] = rotl32(t,  8);                 \
        x[c] += x[d];  t = x[b] ^ x[c];  x[b] = rotl32(t,  7);                 \
    } while (0)

/* Inner keystream generation algorithm. */
static void chacha20_generate(uint8_t dst[64], const uint32_t state[16]) {
    uint32_t x[16];
    uint32_t t;
    int i;

    /* Create a working copy of the current state. */
    memcpy(x, state, 64);

    /* Perform all 20 rounds in batches of 8 quarter-rounds. */
    for (i = 0; i < 20; i += 2) {
        qtr(t, x, 0, 4,  8, 12);
        qtr(t, x, 1, 5,  9, 13);
        qtr(t, x, 2, 6, 10, 14);
        qtr(t, x, 3, 7, 11, 15);

        qtr(t, x, 0, 5, 10, 15);
        qtr(t, x, 1, 6, 11, 12);
        qtr(t, x, 2, 7,  8, 13);
        qtr(t, x, 3, 4,  9, 14);
    }

    /* Mix with previous state. */
    for (i = 0; i < 16; i++)
        x[i] += state[i];

    /* Write the output. */
    for (i = 0; i < 16; i++)
        le32enc(&dst[4*i], x[i]);
}

/* Initialize the context structure. */
void chacha20_init(struct chacha20_ctx * cx, const uint8_t key[32],
                   const uint8_t iv[8]) {
    /* Load constant specific to 256-bit keys. */
    cx->state[ 0] = 0x61707865;  /* "expa" */
    cx->state[ 1] = 0x3320646e;  /* "nd 3" */
    cx->state[ 2] = 0x79622d32;  /* "2-by" */
    cx->state[ 3] = 0x6b206574;  /* "te k" */

    /* Load the key. */
    cx->state[ 4] = le32dec(&key[ 0]);
    cx->state[ 5] = le32dec(&key[ 4]);
    cx->state[ 6] = le32dec(&key[ 8]);
    cx->state[ 7] = le32dec(&key[12]);
    cx->state[ 8] = le32dec(&key[16]);
    cx->state[ 9] = le32dec(&key[20]);
    cx->state[10] = le32dec(&key[24]);
    cx->state[11] = le32dec(&key[28]);

    /* Initialize IV. */
    cx->state[14] = le32dec(&iv[0]);
    cx->state[15] = le32dec(&iv[4]);

    /* Initialize the stream position. */
    cx->offset = 0;
}

/* Seek to an absolute keystream offset. */
void chacha20_seek(struct chacha20_ctx * cx, uint64_t offset) {
    cx->offset = offset;
}

/* Get the current keystream offset. */
uint64_t chacha20_tell(struct chacha20_ctx * cx) {
    return cx->offset;
}

/* XOR `len` bytes from the keystream with `src` into `dst`. The `src` and
 * `dst` slices may only overlap if `dst <= src`. */
void chacha20_xor(struct chacha20_ctx * cx, uint8_t * dst,
                  const uint8_t * src, size_t len) {
    uint8_t tmp[64];
    size_t off, num;
    int i;

    /* Generate the keystream in 64-byte pieces. */
    while (len > 0) {
        /* Update the state with the current offset (divided by 64). */
        cx->state[12] = (uint32_t) (cx->offset >> 6);
        cx->state[13] = (uint32_t) (cx->offset >> 38);

        /* Generate the keystream chunk. */
        off = (size_t) (cx->offset % 64);
        num = (len < 64 - off ? len : 64 - off);

        chacha20_generate(tmp, cx->state);
        for (i = 0; i < num; i++)
            dst[i] = src[i] ^ tmp[i + off];

        /* Move forward. */
        cx->offset += (uint64_t) num;

        dst += num;
        src += num;
        len -= num;
    }
}
