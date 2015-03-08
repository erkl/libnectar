#ifndef NECTAR_SC25519_H
#define NECTAR_SC25519_H

#include "nectar.h"

/* Namespacing. */
#define  sc_muladd  nectar_sc25519_muladd
#define  sc_reduce  nectar_sc25519_reduce

/* Functions. */
void sc_muladd(uint8_t * s, const uint8_t * a, const uint8_t * b, const uint8_t * c);
void sc_reduce(uint8_t * s);

#endif
