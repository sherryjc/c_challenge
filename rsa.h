#pragma once

#include <openssl/bn.h>
#include "utils.h"

// A local implementation of RSA - "JRSA"
class JRSA
{
public:
	JRSA();
	~JRSA();

	bool EncryptBlock(const byte_string& plaintxt, byte_string& ciphertxt, size_t& cnt);
	bool DecryptBlock(const byte_string& cipherBlk, byte_string& plaintext);

	bool EncryptHex(const byte_string& plaintext, byte_string& ctHex);
	bool DecryptHex(const byte_string& ctHex, byte_string& plaintext);

	void PublicKey(BIGNUM** ppE, BIGNUM** ppN);

private:
	void _Init();

	BN_CTX* m_pCtx = nullptr;

	// Modulus N = p*q
	BIGNUM* m_pN = nullptr;

	// Private key D
	BIGNUM* m_pD = nullptr;

	// Public key E
	BIGNUM* m_pE = nullptr;

	static const int c_nPrimeBits{ 512 };
	static const size_t c_nBlockSize{ 256 };

};