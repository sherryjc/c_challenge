#pragma once


#include "utils.h"

// See .cpp file for algorithm details

void HMAC_SHA256(const byte* pKey, size_t keyLen, const byte* pText, size_t textLen, byte* pDigest, size_t digestLen);

void HMAC_SHA256_Test();