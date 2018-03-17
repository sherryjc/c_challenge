
/*
*  Implementation of challenges, Set 5
*/


#include "challenges.h"
#include "utils.h"
#include "n.h"
#include "sha1.h"
#include "aes.h"
#include "sha256.h"
#include "network.h"

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

void _NLibTest()
{
	// Test the imported library delivered in n.h

	// A test from Rosettacode.org
	//Find the last 40 decimal digits of a ^ b, where
	//a = 2988348162058574136915891421498819466320163312926952423791023078876139   
	//b = 2351399303373464486466122544523690094744975233415544072992656881240319 
	// Last 40 decimal digits == modulo 10^40
	// Answer
	// a^b (mod 10^40) = 1527229998585248450016808958343740453059
	// 
	N a("2988348162058574136915891421498819466320163312926952423791023078876139");
	N b("2351399303373464486466122544523690094744975233415544072992656881240319");
	N mb("10");
	N me("40");
	N m = N::w_pow(mb, me);
	std::cout << "10^40 = " << m.s() << std::endl;
	N result;
	math_utils::mod(a, m, result);
	std::cout << "a % m = " << result.s() << std::endl;
	math_utils::mod(b, m, result);
	std::cout << "b % m = " << result.s() << std::endl;
	math_utils::modexp(a, b, m, result);
	std::cout << "a^b % m = " << result.s() << std::endl;
}


bool Challenges::Set5Ch33()
{
	//_intro5_33();
	_NLibTest();
	int g = 2;
	N p(
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff"
	);

	// Need to get a random number uniformly distributed in [1, p-1)
	// Need modexp that can handle a, b, p in that range

	// See Python file Challenges5.py
	// I gave up trying to get a library that will handle large numbers in C++.
	// GMP looks like the best bet but I couldn't get it to install on Windows.
	// In spite of their statement that this is "not hard", getting a C++
	// library written that can handle such large numbers and still finish
	// in reasonable time does not seem to me a trivial task. 

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

	byte_string hash_out;
	SHA2(text1, hash_out);
	bool b1 = io_utils::byteCompare(hash_out, hash1);
	if (!b1) { std::cout << "Test 1 failed" << std::endl; }

	SHA2(text2, hash_out);
	bool b2 = io_utils::byteCompare(hash_out, hash2);
	if (!b2) { std::cout << "Test 2 failed" << std::endl; }

	SHA2(text3, hash_out, 100000);
	bool b3 = io_utils::byteCompare(hash_out, hash3);
	if (!b3) { std::cout << "Test 3 failed" << std::endl; }

	return(b1 && b2 && b3);
}

bool Challenges::Set5Ch36()
{
	bool bResult = _sha256_test();
	std::string result = bResult ? "SUCCEEDED" : "FAILED";
	std::cout << "SHA-256 tests: " <<  result << std::endl;

	// N = NIST Prime = 15073
	// g = 2
	// k = 3


	return bResult;
}

