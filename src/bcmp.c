#include "nectar.h"

/* Safely compare two chunks of memory. */
int safe_bcmp(const uint8_t * buf0, const uint8_t * buf1, size_t len) {
    uint8_t r = 0;
    size_t i;

    for (i = 0; i < len; i++)
        r |= (buf0[i] ^ buf1[i]);

    return (r == 0 ? 0 : -1);
}
