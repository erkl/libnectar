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


/* Utility function which compares two equally sized chunks of memory without
 * leaking any information via timing side channels. Returns 0 if and only if
 * the two chunks are identical. */
int nectar_bcmp(const uint8_t * buf0, const uint8_t * buf1, size_t len) {
    uint8_t r = 0;
    size_t i;

    for (i = 0; i < len; i++)
        r |= (buf0[i] ^ buf1[i]);

    /* Fancy bit twiddling to return either 0 or -1. */
    return (int) ((((r - 1) >> 8) & 1) - 1);
}
