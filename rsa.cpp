
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
	m_pD = BN_new();
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

static void _Compare(BIGNUM* p1, BIGNUM* p2)
{
	if (BN_cmp(p1, p2) != 0) 
	{ 
		std::cout << "Whoa Nellie! The two numbers are different" << std::endl; 
		dbg_utils::dumpBN("p1: ", p1);
		dbg_utils::dumpBN("p2: ", p2);
	}
	else
	{
		std::cout << "The two numbers are the same" << std::endl;
	}
}

bool JRSA::EncryptBlock(const byte_string& plaintxt, byte_string& ciphertxt, size_t& cnt)
{
	BIGNUM* pMsg = BN_new();
	ciphertxt.clear();
	cnt = 0;

	// Encrypt one block of plaintext.
	// Block size - the restriction is to keep the largest possible value smaller than the modulus N.
	// Problem: if you don't keep track of the encrypted sizes of the individual blocks,
	// you won't know where to partition the ciphertext when you try to decrypt.
	// So we:
	//   - encrypt one block
	//   - return how many characters at the start of the string were encrypted
	//     (that is, the next call should advance the start of the string by that amount)
	// This might all be unnecessary, maybe you just fail if the block is too big?

	byte_string block = plaintxt.length() > c_nBlockSize ? plaintxt.substr(0, c_nBlockSize) : plaintxt;

	BIGNUM* pRet = BN_bin2bn(block.c_str(), (int)block.length(), pMsg);
	if (!pRet || !pMsg) return false;

	if (BN_cmp(pMsg, m_pN) > 0) return false;

	// Encrypt: c = m**e % n
	int rc = BN_mod_exp(pMsg, pMsg, m_pE, m_pN, m_pCtx);
	if (0 == rc) return false;

	size_t nBytes = BN_num_bytes(pMsg);
	std::unique_ptr<byte[]> pBin(new byte[nBytes + 1]);
	byte* p = pBin.get();
	rc = BN_bn2bin(pMsg, p);
	if (0 == rc) return false;
	io_utils::FillByteString(ciphertxt, p, nBytes);

	BN_free(pMsg);

	cnt = block.length();
	return true;
}

bool JRSA::DecryptBlock(const byte_string& ciphertxt, byte_string& plaintxt)
{
	plaintxt.clear();
	BIGNUM* pMsg = BN_new();

	// Decrypt the ciphertext a block at a time.
	// The ciphertext passed in corresponds to one block of encrypted plaintext.

	BIGNUM* pRet = BN_bin2bn(ciphertxt.c_str(), (int)ciphertxt.length(), pMsg);
	if (!pRet || !pMsg) return false;

	// Decrypt: m = c**d % n
	int rc = BN_mod_exp(pMsg, pMsg, m_pD, m_pN, m_pCtx);
	if (0 == rc) return false;

	size_t nBytes = BN_num_bytes(pMsg);
	std::unique_ptr<byte[]> pBin(new byte[nBytes + 1]);
	byte* p = pBin.get();
	rc = BN_bn2bin(pMsg, p);
	if (0 == rc) return false;
	io_utils::FillByteString(plaintxt, p, nBytes);

	BN_free(pMsg);

	return true;
}

bool JRSA::EncryptHex(const byte_string& plaintext, byte_string& ctHex)
{

	// First block - TODO, do all blocks
	byte_string block = plaintext.substr(0, sizeof(uint64_t));

	// Approach 1 - via largest int we can handle
	uint64_t val = 0;
	io_utils::BytesBEToUInt64(block.c_str(), block.length(), val);
	BIGNUM* pMsg = BN_new();
	BN_set_word(pMsg, val);

	// Approach 2 - via hex-encoded string


	if (BN_cmp(pMsg, m_pN) > 0)
	{
		std::cout << "Msg block too big!" << std::endl;
		return false;
	}

	// Encrypt: c = m**e % n
	int rc = BN_mod_exp(pMsg, pMsg, m_pE, m_pN, m_pCtx);
	if (0 == rc) { std::cout << "Error, BN_mod_exp" << std::endl; return false; }

	char* pC = BN_bn2hex(pMsg);
	ctHex = reinterpret_cast<byte*>(pC);
	OPENSSL_free(pC);
	BN_free(pMsg);
	return true;
}

bool JRSA::DecryptHex(const byte_string& ctHex, byte_string& plaintext)
{

	BIGNUM* pMsg = nullptr;
	int rc = BN_hex2bn(&pMsg, reinterpret_cast<const char *>(ctHex.c_str()));
	if (0 == rc) { std::cout << "Error, BN_hex2bn" << std::endl; return false; }

	// Decrypt: m = c**d % n
	rc = BN_mod_exp(pMsg, pMsg, m_pD, m_pN, m_pCtx);
	if (0 == rc) { std::cout << "Error, BN_mod_exp" << std::endl; return false; }

	char* pC = BN_bn2hex(pMsg);
	plaintext = reinterpret_cast<byte*>(pC);
	OPENSSL_free(pC);
	BN_free(pMsg);

	return true;
}

void JRSA::PublicKey(BIGNUM** ppE, BIGNUM** ppN)
{
	*ppE = BN_dup(m_pE);
	*ppN = BN_dup(m_pN);
}

