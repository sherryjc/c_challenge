
/*
*  Implementation of challenges, Set 5
*/


#include "challenges.h"
#include "utils.h"
#include "sha1.h"
#include "aes.h"
#include "sha256.h"
#include "network.h"
#include "hmac.h"
#include <openssl/bn.h>
#include <openssl/rand.h>

using namespace io_utils;
using namespace crypto_utils;
using namespace math_utils;

static void _displayModExp(int b, int e, int m)
{
	int res = modexp(b, e, m);
	std::cout << b << " ^ " << e << " mod " << m << " = " << res << std::endl;

}

static void _intro5_33()
{
	_displayModExp(4, 13, 497);  // Answer: 445 (courtesy Wikipedia, "Modular Exponentiation")

	int p = 37;
	int g = 5;

	int a = getRandomNumber() % p;
	int ga = modexp(g, a, p);

	int b = getRandomNumber() % p;
	int gb = modexp(g, b, p);

	int s1 = modexp(ga, b, p);
	int s2 = modexp(gb, a, p);

	std::cout << "Session keys " << s1 << " and " << s2 << std::endl;
}


static void _CheckBNrc(int val)
{
	// BN return codes: 1 on success, 0 on error
	if (0 == val) std::cout << "Operation failed" << std::endl;
}

static void _DisplayCmpResult(int nCmpResult)
{
	std::string resultStr = (0 == nCmpResult) ? "PASSED" : "FAILED";
	std::cout << "Compare operation " << resultStr << std::endl;
}


void _OpenSSLLibTest()
{
	// Test the imported library delivered with OpenSSL

	// A test from Rosettacode.org
	//Find the last 40 decimal digits of a ^ b, where
	//a = 2988348162058574136915891421498819466320163312926952423791023078876139   
	//b = 2351399303373464486466122544523690094744975233415544072992656881240319 
	// Last 40 decimal digits == modulo 10^40
	// Answer
	// a^b (mod 10^40) = 1527229998585248450016808958343740453059
	// 
	// BN_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BN_CTX *ctx);
	// r = a^p
	// BN_mod_exp(BIGNUM* r, BIGNUM* a, BIGNUM* p, const BIGNUM* m, BN_CTX* ctx);
	// r = a^p % m

	std::cout << "Running the OpenSSL library test" << std::endl;

	BN_CTX* pCtx = BN_CTX_new();
	BIGNUM* pA = nullptr;
	BN_dec2bn(&pA, "2988348162058574136915891421498819466320163312926952423791023078876139");
	BIGNUM* pB = nullptr;
	BN_dec2bn(&pB, "2351399303373464486466122544523690094744975233415544072992656881240319");
	BIGNUM* pMB = nullptr;
	BN_dec2bn(&pMB, "10");
	BIGNUM* pME = nullptr;
	BN_dec2bn(&pME, "40");
	BIGNUM* pResult = BN_new();
	BIGNUM* pM = BN_new();
	BN_exp(pM, pMB, pME, pCtx);
	BN_mod_exp(pResult, pA, pB, pM, pCtx);

	std::cout << "a^b % m = " << BN_bn2dec(pResult) << std::endl;
	BIGNUM* pExpected = nullptr;
	BN_dec2bn(&pExpected, "1527229998585248450016808958343740453059");
	std::cout << "Modular exponentiation test" << std::endl;
	_DisplayCmpResult( BN_cmp(pResult, pExpected) );

	std::cout << "Random number tests" << std::endl;
	const byte_string seedStr = reinterpret_cast<byte *>("The quick brown fox jumps over the lazy dog.");
	RAND_seed(seedStr.c_str(), (int)seedStr.length());
	BIGNUM* r1 = BN_new();
	int rc = BN_rand_range(r1, pMB);
	_CheckBNrc(rc);
	std::cout << "random number r1 in [0, 10] = " << BN_bn2dec(r1) << std::endl;

	BIGNUM* r2 = BN_new();
	rc = BN_rand_range(r2, pA);
	_CheckBNrc(rc);
	std::cout << "random number r1 in [0, A] = " << BN_bn2dec(r2) << std::endl;

	BIGNUM* nPrime = BN_new();
	rc = BN_generate_prime_ex(nPrime, 10, 0, nullptr, nullptr, nullptr);
	_CheckBNrc(rc);
	std::cout << "10-bit prime = " << BN_bn2dec(nPrime) << std::endl;

	rc = BN_generate_prime_ex(nPrime, 30, 0, nullptr, nullptr, nullptr);
	_CheckBNrc(rc);
	std::cout << "30-bit prime = " << BN_bn2dec(nPrime) << std::endl;
	rc = BN_generate_prime_ex(nPrime, 50, 0, nullptr, nullptr, nullptr);
	_CheckBNrc(rc);
	std::cout << "50-bit prime = " << BN_bn2dec(nPrime) << std::endl;


	BN_free(pA);
	BN_free(pB);
	BN_free(pM);
	BN_free(pME);
	BN_free(pMB);
	BN_free(pResult);
	BN_free(nPrime);
	BN_CTX_free(pCtx);
}

bool Challenges::Set5Ch33()
{
	//_intro5_33();
	_OpenSSLLibTest();

	std::cout << "Begin 5Ch33" << std::endl;
	// NIST-recommended number given in the exercise (377 decimal digits, roughly equivalent to 1252 bits)
	BIGNUM* p = nullptr;
	BN_dec2bn(&p,
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff"
	);
	BIGNUM* g = BN_new();
	BN_set_word(g, 2);

	BN_CTX* ctx = BN_CTX_new();
	const byte_string seedStr = { 0xd0, 0x96, 0xd0, 0x95, 0xd0, 0x9b, 0xd0, 0x90, 0xd0, 0x9d, 0xd0, 0x9d, 0xd0, 0xac, 0xd0, 0x86, 0xd0, 0x98 };
	RAND_seed(seedStr.c_str(), (int)seedStr.length());

	// TODO
	// I wanted a, b to be random in the range (0, p)
	// But p seems to exceed the maximum allowed by BN_rand_range, although I have seen it work - but usually it fails.
	// So I guess I need to build up a value from multiple calls to BN_rand_range.
	// For now just pick a smaller range.
	BIGNUM* rngUpperBnd = nullptr;
	// We know this value worked from the test code above
	BN_dec2bn(&rngUpperBnd, "2988348162058574136915891421498819466320163312926952423791023078876139");

	BIGNUM* a = BN_new();
	//int rc = BN_rand_range(a, p);
	int rc = BN_rand_range(a, rngUpperBnd);
	_CheckBNrc(rc);
	std::cout << "random number a = " << BN_bn2dec(a) << std::endl;

	BIGNUM* b = BN_new();
	//rc = BN_rand_range(b, p);
	rc = BN_rand_range(b, rngUpperBnd);
	_CheckBNrc(rc);
	std::cout << "random number b = " << BN_bn2dec(b) << std::endl;

	// However, this are also having trouble, presumably p is too large?
	BIGNUM* ga = BN_new();
	rc = BN_mod_exp(ga, g, a, p, ctx);  // ga = g^a mod p
	_CheckBNrc(rc);
	std::cout << "g^a = " << BN_bn2dec(ga) << std::endl;

	BIGNUM* gb = BN_new();
	rc = BN_mod_exp(gb, g, b, p, ctx);  // gb = g^b mod p
	_CheckBNrc(rc);

	BIGNUM* s1 = BN_new();
	rc = BN_mod_exp(s1, ga, b, p, ctx);  // s1 = (ga)^b mod p = g^(ab) mod p
	_CheckBNrc(rc);

	BIGNUM* s2 = BN_new();
	rc = BN_mod_exp(s2, gb, a, p, ctx);  // s1 = (gb)^a mod p = g^(ba) mod p
	_CheckBNrc(rc);

	_DisplayCmpResult( BN_cmp(s1, s2) );
	std::cout << "session key 1 = " << BN_bn2dec(s1) << std::endl;
	std::cout << "session key 2 = " << BN_bn2dec(s2) << std::endl;

	BN_free(p);
	BN_free(g);
	BN_free(a);
	BN_free(b);
	BN_free(ga);
	BN_free(gb);
	BN_free(s1);
	BN_free(s2);
	BN_CTX_free(ctx);

	return true;
}


static void s_Assert(bool bCond, std::string msg)
{
	if (!bCond)
	{
		std::cout << "An error occurred: " << msg << std::endl;
	}
}




static Network s_Network;
static Person Alice("Alice");
static Person Bob("Bob");
static Attacker Malice("Malice");

bool Challenges::Set5Ch34(int arg)   // Also Set5Ch35() for different values of arg
{
	// Set whether or not an MITM attack is taking place
	Malice.m_nAttack = arg;
	Network::SetAttacker(&Malice);

	Network::InitConversation(Alice, Bob, 37, 5);  // p, g

	byte_string strAlice = reinterpret_cast<byte*>("Hello Bob, this is Alice!");
	Network::SendMsg(Alice, Bob, strAlice);

	// Bob sends a response, which includes a copy of Alice's last message
	byte_string strBob = reinterpret_cast<byte*>("Hello Alice, this is Bob! I just got this from you:");
	Network::RespMsg(Bob, Alice, strBob);

	Bob.DisplayLastRecv();
	Alice.DisplayLastRecv();

	// Continue the conversation
	strAlice = reinterpret_cast<byte*>("This is what I have to say - AAAAA");
	Network::SendMsg(Alice, Bob, strAlice);

	// Bob sends a response, which includes a copy of Alice's last message
	strBob = reinterpret_cast<byte*>("B - You said, and I agree: ");
	Network::RespMsg(Bob, Alice, strBob);

	Bob.DisplayLastRecv();
	Alice.DisplayLastRecv();

	return true;
}

static bool _sha256_test()
{
	const byte_string text1{ reinterpret_cast<byte*>("abc") };
	const byte_string text2{ reinterpret_cast<byte*>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") };
	const byte_string text3{ reinterpret_cast<byte*>("aaaaaaaaaa") };
	const byte_string hash1 = { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
		0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
	const byte_string hash2 = { 0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
		0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1 };
	const byte_string hash3 = { 0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
		0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0 };

	s_Assert(hash1.length() == SHA256_BLOCK_SIZE, "SHA2 Hash length");

	//void SHA2(const byte_string& text, byte_string& hash, size_t nUpdates)

	byte hash_out[SHA256_BLOCK_SIZE];
	SHA256(text1.c_str(), text1.length(), hash_out, _countof(hash_out));
	bool b1 = io_utils::byteCompare(hash_out, hash1.c_str(), SHA256_BLOCK_SIZE);
	if (!b1) { std::cout << "Test 1 failed" << std::endl; }

	SHA256(text2.c_str(), text2.length(), hash_out, _countof(hash_out));
	bool b2 = io_utils::byteCompare(hash_out, hash2.c_str(), SHA256_BLOCK_SIZE);
	if (!b2) { std::cout << "Test 2 failed" << std::endl; }

	SHA256(text3.c_str(), text3.length(), hash_out, _countof(hash_out), 100000);
	bool b3 = io_utils::byteCompare(hash_out, hash3.c_str(), SHA256_BLOCK_SIZE);
	if (!b3) { std::cout << "Test 3 failed" << std::endl; }

	return(b1 && b2 && b3);
}

static Server s_Server;

bool Challenges::Set5Ch36()
{
	//bool bResult = _sha256_test();
	// HMAC_SHA256_Test();
	BIGNUM* N = BN_new();
	static const int nPrimeBits = 50;
	int rc = BN_generate_prime_ex(N, nPrimeBits, 0, nullptr, nullptr, nullptr);
	_CheckBNrc(rc);
	int g = 2; 
	int k = 3;
	const byte_string email = reinterpret_cast<byte *>("fred@evilempire.com");
	const byte_string pwd = reinterpret_cast<byte *>("LetMeIn");
	Client client(N, g, k, email, pwd);

	s_Server.Register(client);




	return true;
}

