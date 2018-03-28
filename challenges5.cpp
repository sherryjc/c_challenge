
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

	BIGNUM* nPrime10 = BN_new();
	rc = BN_generate_prime_ex(nPrime10, 10, 0, nullptr, nullptr, nullptr);
	_CheckBNrc(rc);
	std::cout << "10-bit prime = " << BN_bn2dec(nPrime10) << std::endl;

	BIGNUM* nPrime30 = BN_new();
	rc = BN_generate_prime_ex(nPrime30, 30, 0, nullptr, nullptr, nullptr);
	_CheckBNrc(rc);
	std::cout << "30-bit prime = " << BN_bn2dec(nPrime30) << std::endl;

	BIGNUM* nPrime50 = BN_new();
	rc = BN_generate_prime_ex(nPrime50, 50, 0, nullptr, nullptr, nullptr);
	_CheckBNrc(rc);
	std::cout << "50-bit prime = " << BN_bn2dec(nPrime50) << std::endl;

	// NIST-recommended number given in the exercise (377 decimal digits, roughly equivalent to 1252 bits)
	BIGNUM* p = nullptr;
	BN_hex2bn(&p,
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff"
	);

	BIGNUM* pModTest = BN_new();
	BN_mod(pModTest, nPrime50, nPrime30, pCtx);
	std::cout << "50-bit prime mod 30-bit prime = " << BN_bn2dec(pModTest) << std::endl;

	BIGNUM* pMod50bit = BN_new();
	BN_mod(pMod50bit, p, nPrime50, pCtx);
	std::cout << "NIST p mod 50-bit prime = " << BN_bn2dec(pMod50bit) << std::endl;


	BN_free(pA);
	BN_free(pB);
	BN_free(pM);
	BN_free(pME);
	BN_free(pMB);
	BN_free(pResult);
	BN_free(nPrime10);
	BN_free(nPrime30);
	BN_free(nPrime50);
	BN_free(p);
	BN_CTX_free(pCtx);
}

bool Challenges::Set5Ch33()
{
	//_intro5_33();
	_OpenSSLLibTest();

	std::cout << "Begin 5Ch33" << std::endl;
	// NIST-recommended number given in the exercise (377 decimal digits, roughly equivalent to 1252 bits)
	BIGNUM* p = nullptr;
	BN_hex2bn(&p,
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

	// Want a, b to be random in the range (0, p)
	// But p seems to exceed the maximum allowed by BN_rand_range, although I have seen it work - but usually it fails.
	// So I guess I need to build up a value from multiple calls to BN_rand_range.
	// For now just pick a smaller range.

	BIGNUM* a = BN_new();
	int rc = BN_rand_range(a, p);
	_CheckBNrc(rc);
	std::cout << "random number a = " << BN_bn2dec(a) << std::endl;

	BIGNUM* b = BN_new();
	rc = BN_rand_range(b, p);
	_CheckBNrc(rc);
	std::cout << "random number b = " << BN_bn2dec(b) << std::endl;

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

static void _displayGCD(int a, int b)
{
	std::cout << "gcd(" << a << "," << b << ") = " << gcd(a, b) << std::endl;

}

static void _displayExtendedGCD(int a, int b, int gcd, int lambda, int mu)
{
	std::string eq = " = ";
	if ((a*lambda + b*mu) != gcd)
	{
		std::cout << "FAILED verification of lambda and mu values" <<  std::endl;
		eq = " != ";
	}
	std::cout << "gcd(" << a << "," << b << ") = " << gcd << eq << "(" << lambda << ")a" << " + (" << mu << ")b" << std::endl;

}

static void _gcd_test()
{
	_displayGCD(108, 42);
	_displayGCD(42, 108);        // see if we handle backwards order
	_displayGCD(1084573620, 9);  // note digits sum to a multiple of 9
	_displayGCD(1084573621, 9);  // note digits sum to a multiple of 9 + 1
	_displayGCD(1084573623, 9);  // note digits sum to a multiple of 3 (multiple of 9 + 3)
	_displayGCD(7907, 6389);     // both prime

}

static void _extended_gcd_test(int a, int b)
{
	int lambda = 0, mu = 0;
	int gcd1 = gcd(a, b);
	int gcd = extended_gcd(a, b, lambda, mu);
	if (gcd != gcd1) 
	{
		std::cout << "GCDs do not match!!" << std::endl;
	}
	_displayExtendedGCD(a, b, gcd, lambda, mu);
}

static void _invmod_test(int a, int m)
{
	int a_inv = 0;
	bool bHasInv = invmod(a, m, a_inv);
	if (!bHasInv)
	{
		std::cout << "a does not have an inverse mod m" << std::endl;
		return;
	}
	// Check our answer
	if (!checkInvMod(a, a_inv, m))
	{
		std::cout << "The inverse returned by invmod does not compute!" << std::endl;
	}
	std::cout << "The inverse of " << a << " mod " << m << " = " << a_inv << std::endl;
}

static void SendRecvMsg(int msg, int e, int d, int n)
{
	// Encrypt: c = m**e % n
	int c = modexp(msg, e, n);

	// Decrypt: m = c**d % n
	int msg2 = modexp(c, d, n);

	std::cout << "Sending message: " << msg << std::endl;
	if (msg != msg2)
	{
		std::cout << "FAILED! " << msg << " != " << msg2 << std::endl;

	}
	else
	{
		std::cout << "PASSED " << msg << " == " << msg2 << std::endl;
	}
}

bool Challenges::Set5Ch39()
{
	//_gcd_test();
	//_extended_gcd_test(240, 46);
	//_extended_gcd_test(7907, 6389);
	_invmod_test(17, 3120);   // 2753

	// Generate random primes p and q
	//int p = 19423;
	//int q = 89371;
	int p = 43;
	int q = 37;

	// Set n = p*q.  RSA math will be mod n
	int n = p*q;

	// Euler's totient = number of integers that are relatively prime to n, i.e. # of k for which gcd(k, n) = 1
	// et = phi(n) = (p-1)*(q-1) 
	int phi_n = (p - 1)*(q - 1);

	// Set e = 3
	// more generally, this is a random number e < phi(n) relatively prime to phi(n), i.e. such that gcd(e, phi(n)) = 1
	// Just hard-wiring this to 3, as instructed in the Challenge, will not work for some choices of p and q.
	// So I am going to start at e = 3 and increment until I find the first one that is relatively prime to phi(n).
	// Not exactly random, but neither is hard-wiring it to 3.

	int e = 3;

	while (gcd(e, phi_n) != 1) { ++e; }

	std::cout << "Found e = " << e << std::endl;
	std::cout << "n = " << n << " phi(n) = " << phi_n << std::endl;

	// compute d = invmod(e, phi(n)), that is:  d = inv(e) modulo phi(n)
	// this means find d such that d*e mod phi(n) = 1
	int d = 0;
	bool bHasInv = invmod(e, phi_n, d);
	if (!bHasInv)
	{
		std::cout << "Big problem, couldn't invert e !!!" << std::endl;
	}

	// Let's do a little sanity check
	if (!checkInvMod(e, d, phi_n))
	{
		std::cout << "The inverse we got didn't pan out!!!" << std::endl;
	}

	std::cout << "e = " << e << " d = " << d << std::endl;

	// the public key is [e,n], the private key is [d,n]
	// Encrypt: c = m**e % n
	// Decrypt: m = c**d % n
	// Note that m must be less than n. Otherwise we have to break m into chunks.

	int m = 42; // the message
	SendRecvMsg(m, e, d, n);

	m = 1590;
	SendRecvMsg(m, e, d, n);


	return true;
}

static bool _Set5Ch40FirstCut()
{
/* 
	He gives this expression for result (== m**3)
	result =
		(c_0 * m_s_0 * invmod(m_s_0, n_0)) +
		(c_1 * m_s_1 * invmod(m_s_1, n_1)) +
		(c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012

	where:
	c_0, c_1, c_2 are the three respective residues mod n_0, n_1, n_2

	m_s_n(for n in 0, 1, 2) are the product of the moduli
	EXCEPT n_n-- - ie, m_s_1 is n_0 * n_2

	N_012 is the product of all three moduli
	=================================================

	See derivation p. 21, Koblitz.
*/

	// Problems encountered:
	// I was trying to get away with using integers, which means the message and the primes can't get very big
	// I thought I could just manually select 3 pq pairs, but it was hard to find 3 different pairs that
	// met both the Phi condition and being pairwise coprime.
	// So eventually I will rewrite this using BIGNUMs.

	// We want three different n(i) that can be used with e = 3
	//int p[3] = { 1709, 1487, 1553 };
	//int q[3] = { 2207, 2027, 2027 };
	int p[3] = { 59, 97, 53 };
	int q[3] = { 41, 37, 23 };
	int e = 3;
	int n[3] = { 0 };
	int phi_n[3] = { 0 };
	int msg = 187;
	int c[3] = { 0 };
	int invm[3] = { 0 };



	for (size_t ii = 0; ii < 3; ++ii)
	{
		n[ii] = p[ii] * q[ii];
		phi_n[ii] = (p[ii] - 1)*(q[ii] - 1);
		if (gcd(e, phi_n[ii]) == 1)
		{
			std::cout << "Pair " << ii << " ==> OK" << std::endl;
		}
		else
		{
			std::cout << "Pair " << ii << " ==> NO GOOD" << std::endl;
		}
		if (msg > n[ii])
		{
			std::cout << "Message is too big, break it in chunks" << std::endl;
		}

		// Encrypt the message with this key
		c[ii] = modexp(msg, e, n[ii]);

	}

	// The n[ii] need to be pairwise coprime
	if (gcd(n[0], n[1]) != 1)
	{
		std::cout << "n[0], n[1]" << " ==> NOT coprime" << std::endl;
	}
	if (gcd(n[0], n[2]) != 1)
	{
		std::cout << "n[0], n[2]" << " ==> NOT coprime" << std::endl;
	}
	if (gcd(n[1], n[2]) != 1)
	{
		std::cout << "n[0], n[1]" << " ==> NOT coprime" << std::endl;
	}

	// Note we haven't recovered d, which would requite an inverse exponential. 
	// Here we are just taking the inverse of a product of two keys 
	// If there we any failures in the coprime check, taking inverses will fail here.
	bool bInv = invmod(n[1] * n[2], n[0], invm[0]);
	if (!bInv)
	{
		std::cout << "Failed getting inverse for n[1], n[2] mod n[0]" << std::endl;
	}
	bInv = invmod(n[0] * n[2], n[1], invm[1]);
	if (!bInv)
	{
		std::cout << "Failed getting inverse for n[0], n[2] mod n[1]" << std::endl;
	}
	bInv = invmod(n[0] * n[1], n[2], invm[2]);
	if (!bInv)
	{
		std::cout << "Failed getting inverse for n[0], n[1] mod n[2]" << std::endl;
	}

	int msg_pow3 = (c[0] * n[1] * n[2] * invm[0]) + (c[1] * n[0] * n[2] * invm[1]) + (c[2] * n[0] * n[1] * invm[2]);

	std::cout << "Msg sent = " << msg << std::endl;
	std::cout << "Msg cubed = " << msg_pow3 << std::endl;


	return true;
}

bool Challenges::Set5Ch40()
{

	return false;
}