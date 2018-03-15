
/*
*  Implementation of challenges, Set 5
*/


#include "challenges.h"
#include "utils.h"
#include "n.h"
#include "sha1.h"
#include "aes.h"

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

typedef struct person_t {
	int p;
	int g;
	int secret;   // a or b, random in [0,p)
	int g_exp_own;
	int g_exp_other;
	int dh_key;
	byte_string aes_key;
	byte_string recv_msg_encr; // Last received message - ciphertext
	byte_string recv_msg_decr; // Last received message - plaintext
} Person;

Person Alice;
Person Bob;
Person Malice;

void _Send(Person& rec, int p, int g, int gx)
{
	rec.p = p;
	rec.g = g;
	rec.g_exp_other = gx;
}

void _Send(Person& rec, int gx)
{
	rec.g_exp_other = gx;
}

void _DH_to_AES(int dh_key, byte_string& aes_key)
{
	aes_key.clear();
	static const size_t kAESblockSz = 16;
	char result[kDigestSize + 1];
	char buf[sizeof(int)+1];
	sprintf_s(buf, _countof(buf), "%4d", dh_key);
	SHA1(result, buf, sizeof(int));
	for (size_t ii = 0; ii < kAESblockSz; ++ii)
	{
		aes_key += result[ii];
	}
}

void _SendMsg(Person& from, Person& to, const byte_string& msg, bool bIncludePrev)
{
	Aes aes(128);
	aes.SetMode(Aes::CBC);
	aes.SetKey(from.aes_key.c_str(), from.aes_key.length());
	aes.SetInitializationVector(Aes::RANDOM);
	byte_string iv;
	aes.InitializationVector(iv);

	// If specified, append the last received message to the message we're sending
	byte_string sendMsg = msg;
	if (bIncludePrev)
	{
		sendMsg.append(reinterpret_cast<byte*>(":"));
		sendMsg.append(from.recv_msg_decr);
	}
	// The IV is being sent as a part of the message just to have a random parameter 
	// (which the attacker will change in a later step).
	sendMsg.append(iv);
	aes.SetInput(sendMsg, true /*pad*/);

	aes.Encrypt();

	// Here is where the message gets "sent" - it shows up in the encrypted in-box of the receiver
	aes.ResultStr(to.recv_msg_encr);
}

void _RecvMsg(Person& rec)
{
	// Receiver checks his/her in-box, decrypts what's there
	if (rec.recv_msg_encr.length() == 0) return;

	Aes aes(128);
	aes.SetMode(Aes::CBC);
	aes.SetKey(rec.aes_key.c_str(), rec.aes_key.length());
	aes.Decrypt();
	aes.ResultStr(rec.recv_msg_decr);

	// Discard the encrypted message
	rec.recv_msg_decr.clear();
}


bool Challenges::Set5Ch34()
{
	Alice.p = 37;
	Alice.g = 5;
	Alice.secret = getRandomNumber() % Alice.p;
	Alice.g_exp_own = modexp(Alice.g, Alice.secret, Alice.p);
	_Send(Bob, Alice.p, Alice.g, Alice.g_exp_own);

	Bob.secret = getRandomNumber() % Bob.p;
	Bob.g_exp_own = modexp(Bob.g, Bob.secret, Bob.p);
	_Send(Alice, Bob.g_exp_own);

	Alice.dh_key = modexp(Alice.g_exp_other, Alice.secret, Alice.p);
	Bob.dh_key = modexp(Bob.g_exp_other, Bob.secret, Bob.p);

	// Sanity check
	if (Alice.dh_key != Bob.dh_key)
	{
		std::cout << "Something has gone horribly wrong with the DH Session Key" << std::endl;
	}

	// Alice and Bob each compute the AES key
	_DH_to_AES(Alice.dh_key, Alice.aes_key);
	_DH_to_AES(Bob.dh_key, Bob.aes_key);

	// Another sanity check
	if (Alice.aes_key != Bob.aes_key)
	{
		std::cout << "Something has gone horribly wrong with the AES Session Key" << std::endl;
	}

	byte_string strAlice = reinterpret_cast<byte*>("Hello Bob, this is Alice!");
	_SendMsg(Alice, Bob, strAlice, false);

	_RecvMsg(Bob);

	// Bob sends a response, and includes a copy of Alice's message (the final bool arg)
	byte_string strBob = reinterpret_cast<byte*>("Hello Alice, this is Bob! I just got this from you:");
	_SendMsg(Bob, Alice, strBob, true);

	_RecvMsg(Alice);

	std::cout << "Last message Bob received: " << Bob.recv_msg_decr.c_str() << std::endl;
	std::cout << "Last message Alice received: " << Alice.recv_msg_decr.c_str() << std::endl;

	return true;
}

