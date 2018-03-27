
#include "rsa.h"
#include <iostream>

JRSA::JRSA()
{
	_Init();
}

JRSA::~JRSA()
{
	if (m_pCtx)	BN_CTX_free(m_pCtx);
	if (m_pN) BN_free(m_pN);
}

void JRSA::_Init()
{
	m_pCtx = BN_CTX_new();
	BN_CTX* m_pCtx = BN_CTX_new();

	// Get the primes p and q
	BIGNUM* p = BN_new();
	int rc = BN_generate_prime_ex(p, c_nPrimeBits, 0, nullptr, nullptr, nullptr);
	if (0 == rc) { std::cout << "Error, BN_generate_prime_ex" << std::endl; return; }

	BIGNUM* q = BN_new();
	rc = BN_generate_prime_ex(q, c_nPrimeBits, 0, nullptr, nullptr, nullptr);
	if (0 == rc) { std::cout << "Error, BN_generate_prime_ex" << std::endl; return; }

	// Set N = p*q.  RSA math will be mod N
	m_pN = BN_new();
	rc = BN_mul(m_pN, p, q, m_pCtx);
	if (0 == rc) { std::cout << "Error, BN_mul" << std::endl; return; }

	// p now holds p-1
	rc = BN_sub(p, p, BN_value_one());
	if (0 == rc) { std::cout << "Error, BN_sub" << std::endl; return; }

	// q now holds q-1
	rc = BN_sub(q, q, BN_value_one());
	if (0 == rc) { std::cout << "Error, BN_sub" << std::endl; return; }

	// Phi function (Euler's totient) = number of integers that are relatively prime to n, i.e. # of k for which gcd(k, n) = 1
	// phi(n) = (p-1)*(q-1) 
	BIGNUM* phi = BN_new();
	rc = BN_mul(phi, p, q, m_pCtx);
	if (0 == rc) { std::cout << "Error, BN_mul" << std::endl; return; }


	// Set e to a random number < phi(n) relatively prime to phi(n), i.e. such that gcd(e, phi(n)) = 1
	// Rather than random, will start with 3 and increment until will find one that is relatively prime to phi.
	m_pE = BN_new();
	BN_set_word(m_pE, 3);
	BIGNUM* res = BN_new();
	while (true)
	{
		rc = BN_gcd(res, m_pE, phi, m_pCtx);
		if (0 == rc) { std::cout << "Error, BN_gcd" << std::endl; return; }

		if (BN_cmp(res, BN_value_one()) == 0) break;

		rc = BN_add(m_pE, m_pE, BN_value_one());
		if (0 == rc) { std::cout << "Error, BN_add" << std::endl; return; }
	}

	// compute d = invmod(e, phi(n)), that is:  d = inv(e) modulo phi(n)
	// this means find d such that d*e mod phi(n) = 1
	BIGNUM* pRc = BN_mod_inverse(m_pD, m_pE, phi, m_pCtx);
	if (!pRc)
	{
		std::cout << "Big problem, couldn't invert e !!!" << std::endl;
	}

	// the public key is [e,n], the private key is [d,n]
	// Encrypt: c = m**e % n
	// Decrypt: m = c**d % n
	// Note that m must be less than n. Otherwise we have to break m into chunks.

	// Throw away p, q, phi. The values we need are now in member variables.
	BN_free(p);
	BN_free(q);
	BN_free(phi);

}

bool JRSA::Encrypt(const byte_string& plaintext, byte_string& ciphertext)
{
	const byte* pPlaintxt = plaintext.c_str();

	byte m_workingBuf[c_nBlockSize + 1]{ 0 };


	// First block - TODO, do all blocks
	byte_string block = plaintext.substr(0, c_nBlockSize);
	unsigned long long ull = dbg_utils::toULongLong(block);

	BIGNUM* pMsg = BN_new();
	BN_set_word(pMsg, ull);

	std::cout << "Msg as bignum = " << BN_bn2hex(pMsg) << std::endl;
	if (BN_cmp(pMsg, m_pN) > 0)
	{
		std::cout << "Msg block too big! = " << std::endl;
		return false;
	}
	// Encrypt: c = m**e % n
	int rc = BN_mod_exp(pMsg, pMsg, m_pE, m_pN, m_pCtx);
	if (0 == rc) { std::cout << "Error, BN_mod_exp" << std::endl; return false; }

	// Iterate through the bytes of pMsg
	// TODO - figure out how
	size_t nBytes = BN_num_bytes(pMsg);
	for (size_t ii = 0; ii < nBytes; ++ii)
	{
		//ciphertext += *pBytes++;
	}
	BN_free(pMsg);
	return true;
}

bool JRSA::Decrypt(const byte_string& ciphertext, byte_string& plaintext)
{
	// Decrypt: m = c**d % n
	// int msg2 = modexp(c, d, n);

	return false;
}
