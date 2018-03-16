
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


static void s_Assert(bool bCond, std::string msg)
{
	if (!bCond)
	{
		std::cout << "An error occurred: " << msg << std::endl;
	}
}


class Person {
public:
	Person(const std::string& name);
	~Person() {}

	void Init(int p, int g, int gx=0);
	void CompleteInit(int gx);
	void ComputeAes();
	void SendMsg(Person& to, const byte_string& msg, bool bIncludePrev=false);
	void RespMsg(Person& to, const byte_string& msg);
	void RecvMsg();				// Prod receiver to check inbox
	void ExtractIv(byte_string& iv);
	void DisplayLastRecv();		// Display last received message
	void DumpAll();				// Dump all information for this person

	// data members
	std::string m_name;

	int m_p{ 0 };
	int m_g{ 0 };
	int m_secret{ 0 };   // a or b, random in [0,p)
	int m_g_exp_own{ 0 };
	int m_g_exp_other{ 0 };
	int m_dh_key{ 0 };
	byte_string m_aes_key;
	byte_string m_recv_msg_encr; // Last received message - ciphertext
	byte_string m_recv_msg_decr; // Last received message - plaintext

	static const size_t c_kAESblockSz = 16;
};

class Attacker {
public:
	Attacker(const std::string& name);
	~Attacker() {};

	void InterceptInit(Person& from, Person& to, int p, int g);
	void InterceptMsg(Person& from, Person& to, const byte_string& msg);
	void ComputeAes();
	void ExamineMsg(byte_string encrMsg);

	// data
	std::string m_name;

	int m_p{ 0 };
	int m_g{ 0 };
	int m_dh_key{ 0 };
	byte_string m_aes_key;

};

class Network {
public:
	Network() { }
	static void InitConversation(Person& from, Person& to, int p, int g);
	static void SendMsg(Person& from, Person& to, const byte_string& msg);
	static void RespMsg(Person& from, Person& to, const byte_string& msg);
	static void SetAttacker(Attacker* pAttacker);
	static Attacker* c_pAttacker;
};

Attacker* Network::c_pAttacker = nullptr;

void Network::InitConversation(Person& from, Person& to, int p, int g)
{
	if (c_pAttacker)
	{
		c_pAttacker->InterceptInit(from, to, p, g);
		return;
	}

	from.Init(p, g);

	// "From" sends p, g, gx to "To"
	to.Init(from.m_p, from.m_g, from.m_g_exp_own);

	// "To" responds with its gx so "From" can complete its initialization
	from.CompleteInit(to.m_g_exp_own);
}

void Network::SendMsg(Person& from, Person& to, const byte_string& msg)
{
	if (c_pAttacker)
	{
		c_pAttacker->InterceptMsg(from, to, msg);
		return;
	}

	from.SendMsg(to, msg);
	to.RecvMsg();
}

void Network::RespMsg(Person& from, Person& to, const byte_string& msg)
{
	if (c_pAttacker)
	{
		c_pAttacker->InterceptMsg(from, to, msg);  // No difference between send and response for attacker
		return;
	}

	from.RespMsg(to, msg);
	to.RecvMsg();
}

void Network::SetAttacker(Attacker* pAttacker)
{
	c_pAttacker = pAttacker;
}


Person::Person(const std::string& name)
	:m_name(name)
{}

void Person::Init(int p, int g, int gx)
{
	m_p = p;
	m_g = g;
	m_g_exp_other = gx;   // May be 0 if we are the first to init

	// Compute our own values
	m_secret = getRandomNumber() % m_p;
	m_g_exp_own = modexp(m_g, m_secret, m_p);

	if (0 != m_g_exp_other)   // == 0: we need to wait until the other side has init'd
	{
		CompleteInit(m_g_exp_other);
	}
}

void Person::CompleteInit(int gx)
{
	s_Assert(gx != 0, "CompleteInit");

	m_g_exp_other = gx;   
	m_dh_key = modexp(m_g_exp_other, m_secret, m_p);
	ComputeAes();
}

void Person::ComputeAes()
{
	// This assert fires when M tampers with our protocol.
	// It seems like this would make it obvious that something was wrong.
	// s_Assert(m_dh_key > 0, "DH==0 in ComputeAes");
	if (m_dh_key == 0)
	{
		std::cout << "Warning: Network tampering detected by " << m_name << std::endl;
	}

	m_aes_key.clear();
	char result[kDigestSize + 1];
	char buf[sizeof(int) + 1];
	sprintf_s(buf, _countof(buf), "%4d", m_dh_key);
	SHA1(result, buf, sizeof(int));
	for (size_t ii = 0; ii < c_kAESblockSz; ++ii)
	{
		m_aes_key += result[ii];
	}
}

void Person::SendMsg(Person& to, const byte_string& msg, bool bIncludePrev)
{
	Aes aes(128);
	aes.SetMode(Aes::CBC);
	aes.SetKey(m_aes_key.c_str(), m_aes_key.length());
	aes.SetInitializationVector(Aes::RANDOM);
	byte_string iv;
	aes.InitializationVector(iv);

	// If specified, append the last received message to the message we're sending
	byte_string sendMsg = msg;
	if (bIncludePrev)
	{
		sendMsg.append(reinterpret_cast<byte*>(":"));
		// Handle the fact that append wants a null-terminated c-style string
		byte_string returnMsg = m_recv_msg_decr;
		byte* pBytes = const_cast<byte*>(returnMsg.c_str());
		pBytes[returnMsg.length() - 1] = '\0';
		sendMsg.append(returnMsg);
	}
	aes.SetInput(sendMsg, true /*pad*/);
	aes.Encrypt();
	byte_string encryptedMsg;
	aes.ResultStr(encryptedMsg);
	// Append the initialization vector we used
	encryptedMsg.append(iv);

	// Here is where the message gets "sent" - it shows up in the encrypted in-box of the receiver
	to.m_recv_msg_encr = encryptedMsg;
}

void Person::RespMsg(Person& to, const byte_string& msg)
{
	SendMsg(to, msg, true);
}

void Person::RecvMsg()
{
	// Receiver checks his/her in-box, decrypts what's there
	if (m_recv_msg_encr.length() == 0) return;

	Aes aes(128);
	aes.SetMode(Aes::CBC);
	aes.SetKey(m_aes_key.c_str(), m_aes_key.length());

	// Strip off the initialization vector from the end of the sent message (before decrypting)
	byte_string iv;
	ExtractIv(iv);
	aes.SetInitializationVector(iv);
	aes.SetInput(m_recv_msg_encr);  // Note iv has now been stripped off

	aes.Decrypt();
	aes.ResultStr(m_recv_msg_decr);
}

void Person::ExtractIv(byte_string& iv)
{
	size_t len = m_recv_msg_encr.length();
	size_t startIdx = len - c_kAESblockSz;
	iv = m_recv_msg_encr.substr(startIdx, c_kAESblockSz);
	m_recv_msg_encr = m_recv_msg_encr.substr(0, startIdx);
}

void Person::DisplayLastRecv()
{
	std::cout << std::endl << "Last message " << m_name << " received: " << std::endl << "### ";
	dbg_utils::displayByteStrAsCStr(m_recv_msg_decr);
	std::cout << std::endl;

}

void Person::DumpAll()
{
	std::cout << "Name:           " << m_name << std::endl;
	std::cout << "p =             " << m_p << std::endl;
	std::cout << "g =             " << m_g << std::endl;
	std::cout << "secret =        " << m_secret << std::endl;
	std::cout << "my g^x =        " << m_g_exp_own << std::endl;
	std::cout << "other g^x =     " << m_g_exp_other << std::endl;
	std::cout << "DH Key =        " << m_dh_key << std::endl;
	std::cout << "AES Key =       "; 
	dbg_utils::displayHex(m_aes_key);
	std::cout << std::endl;
	std::cout << "Rcv msg (C) =   ";
	dbg_utils::displayHex(m_recv_msg_encr);
	std::cout << std::endl;
	std::cout << "Rcv msg (P) =   ";
	dbg_utils::displayByteStrAsCStr(m_recv_msg_decr);
	std::cout << std::endl;
}

Attacker::Attacker(const std::string& name)
	:m_name(name)
{
}


void Attacker::InterceptInit(Person& from, Person& to, int p, int g)
{
	std::cout << "Attacker \"" << m_name << "\" is listening!" << std::endl;

	m_p = p;
	m_g = g;

	from.Init(p, g);

	// Let "from" = A, "to" = B
	// Instead of sending  p, g, gx to B, send p, g, p to B
	to.Init(m_p, m_g, m_p);

	// B responds with its gx so A can complete its initialization
	// But instead we pass back p again
	from.CompleteInit(m_p);

	// At this point we can conclude:
	//   - The common DH Key computed by A and B will be 0
	//   - The common AES key computed by A and B will be SHA1(0)
	// So we just compute SHA1(0) and hold onto it
	m_dh_key = 0;  // not really necessary, was set to 0 in ctor, but let's be clear
	ComputeAes();
}

void Attacker::InterceptMsg(Person& from, Person& to, const byte_string& msg)
{
	std::cout << "Attacker passing along message from " << from.m_name << " to " << to.m_name << std::endl;

	from.SendMsg(to, msg);
	ExamineMsg(to.m_recv_msg_encr);

	to.RecvMsg();
}

void Attacker::ExamineMsg(byte_string encrMsg)   // Note - encrMsg not &, working on a copy
{
	if (encrMsg.length() == 0) return;

	Aes aes(128);
	aes.SetMode(Aes::CBC);
	aes.SetKey(m_aes_key.c_str(), m_aes_key.length());

	// Strip off the initialization vector from the end of the sent message (before decrypting)
	size_t len = encrMsg.length();
	size_t startIdx = len - Person::c_kAESblockSz;
	byte_string iv = encrMsg.substr(startIdx, Person::c_kAESblockSz);
	encrMsg = encrMsg.substr(0, startIdx);
	aes.SetInitializationVector(iv);
	aes.SetInput(encrMsg);  // Note iv has now been stripped off

	aes.Decrypt();
	byte_string decrMsg;
	aes.ResultStr(decrMsg);
	std::cout << "*** " << decrMsg.c_str() << std::endl;
}

void Attacker::ComputeAes()
{
	m_aes_key.clear();
	char result[kDigestSize + 1];
	char buf[sizeof(int) + 1];
	sprintf_s(buf, _countof(buf), "%4d", m_dh_key);
	SHA1(result, buf, sizeof(int));
	for (size_t ii = 0; ii < Person::c_kAESblockSz; ++ii)
	{
		m_aes_key += result[ii];
	}
}

static Network s_Network;
static Person Alice("Alice");
static Person Bob("Bob");
static Attacker Malice("Malice");

bool Challenges::Set5Ch34()
{
	// Set whether or not an MITM attack is taking place
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

