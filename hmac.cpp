

#include "hmac.h"
#include "sha256.h"

using namespace io_utils;

/*
	RFC 2104

	B  Byte length of input data blocks
	= 64 for SHA-2 (and SHA-1)
	L  Length of hash outputs (digest)
	= 32 for SHA-2, 20 for SHA-1
	K  Key, can be any length up to B
	recommended minimum = L
	H  Hash function being used
	Here: H(a, b) means append b to a, then hash the resulting string

	ipad, opad (inner, outer)
	ipad = 0x36 repeated B times
	opad = 0x5C repeated B times

	HMAC(text) = H(K XOR opad, H(K XOR ipad, text))

	Details:
	(1) append zeros to the end of K to create a B byte string
	(e.g., if K is of length 20 bytes and B=64, then K will be appended with 44 zero bytes 0x00)
	(2) XOR (bitwise exclusive-OR) the B byte string computed in step(1) with ipad
	(3) append the stream of data 'text' to the B byte string resulting from step (2)
	(4) apply H to the stream generated in step (3)
	(5) XOR (bitwise exclusive-OR) the B byte string computed in step (1) with opad
	(6) append the H result from step (4) to the B byte string resulting from step (5)
	(7) apply H to the stream generated in step (6) and output the result
*/

static const int kHMAC_SHA256_B = 64;     // Input block length in bytes
static const int kHMAC_SHA256_DLEN = 32;  // Output (digest) length in bytes
static const byte kIPadCh = 0x36;
static const byte kOPadCh = 0x5c;

void HMAC_SHA256(const byte* pKey, size_t keyLen, const byte* pText, size_t textLen, byte* pDigest, size_t digestLen)
{
	if (keyLen > kHMAC_SHA256_B)
	{
		// TODO: hash the key once, use the digest as input to HMAC
		std::cout << "Long keys not implemented yet" << std::endl;
		return;
	}

	if (digestLen < kHMAC_SHA256_DLEN)
	{
		std::cout << "Output buffer not big enough to hold SHA256 digest" << std::endl;
		return;
	}

	byte ipad[kHMAC_SHA256_B + 1]{ 0 };
	byte opad[kHMAC_SHA256_B + 1]{ 0 };

	// Start out with key in ipad, opad
	byteCopy(ipad, _countof(ipad), pKey, keyLen);
	byteCopy(opad, _countof(opad), pKey, keyLen);

	/* XOR key with ipad and opad values */
	byte* pIPad = ipad;
	byte* pOPad = opad;
	for (size_t ii = 0; ii < kHMAC_SHA256_B; ++ii) {
		*pIPad++ ^= kIPadCh;
		*pOPad++ ^= kOPadCh;
	}

	// "Inner" portion
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, ipad, kHMAC_SHA256_B);
	sha256_update(&ctx, pText, textLen);
	sha256_final(&ctx, pDigest);

	// "Outer" portion
	sha256_init(&ctx);
	sha256_update(&ctx, opad, kHMAC_SHA256_B);
	sha256_update(&ctx, pDigest, kHMAC_SHA256_DLEN);
	sha256_final(&ctx, pDigest);
}

void HMAC_SHA256_Test()
{
	// Test vectors from RFC 4231

	std::cout << "HMAC-SHA256 tests" << std::endl;
	// Test case 1
	// Key = 20 bytes of 0b
	byte key[20]{ 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

	// Data = 4869205468657265 ("Hi There")
	byte data[] = { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };

	//HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
	byte digest[] = { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
					  0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 };

	byte result[kHMAC_SHA256_DLEN];
	HMAC_SHA256(key, _countof(key), data, _countof(data), result, _countof(result));
	bool b = byteCompare(digest, result, kHMAC_SHA256_DLEN);
	std::string resultStr = b ? "PASSED" : "FAILED";
	std::cout << "Test 1: " << resultStr << std::endl;

}

