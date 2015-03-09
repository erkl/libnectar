#ifndef LIBNECTAR_25519_SC_H
#define LIBNECTAR_25519_SC_H

#include "nectar.h"

/* Namespacing. */
#define  sc_muladd  nectar__25519_sc_muladd
#define  sc_reduce  nectar__25519_sc_reduce

/* Functions. */
void sc_muladd(uint8_t * s, const uint8_t * a, const uint8_t * b, const uint8_t * c);
void sc_reduce(uint8_t * s);

#endif
