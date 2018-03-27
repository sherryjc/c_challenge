#pragma once

#include <openssl/bn.h>
#include "utils.h"

// A local implementation of RSA - "JRSA"
class JRSA
{
public:
	JRSA();
	~JRSA();

	bool Encrypt(const byte_string& plaintext, byte_string& ciphertext);
	bool Decrypt(const byte_string& ciphertext, byte_string& plaintext);

private:
	void _Init();

	BN_CTX* m_pCtx = nullptr;

	// Modulus N = p*q
	BIGNUM* m_pN = nullptr;

	// Private key D
	BIGNUM* m_pD = nullptr;

	// Public key E
	BIGNUM* m_pE = nullptr;

	static const int c_nPrimeBits{ 40 };
	static const size_t c_nBlockSize{ 16 };  // How many characters we work with at a time

	byte m_workingBuf[c_nBlockSize + 1]{ 0 };

};