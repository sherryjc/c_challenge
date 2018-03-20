#ifndef SHA1_H
#define SHA1_H

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include "stdint.h"
#include "utils.h"
constexpr size_t kDigestSize = 20;

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    byte buffer[64];
} SHA1_CTX;

void SHA1Transform(
    uint32_t state[5],
    const byte buffer[64]
    );

void SHA1Init(
    SHA1_CTX * context
    );

void SHA1Update(
    SHA1_CTX * context,
    const byte *data,
    uint32_t len
    );

void SHA1Final(
    byte digest[kDigestSize],
    SHA1_CTX * context
    );

void SHA1(
    byte *hash_out,
    const byte *str,
    size_t len);

void SHA1_Test_RunAll();


#endif /* SHA1_H */
