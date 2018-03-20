
#include "network.h"
#include "sha1.h"
#include "sha256.h"
#include "aes.h"

using namespace crypto_utils;
using namespace math_utils;

// Implementation of class Network

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


// Implementation of class Person

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

	if (-1 != m_g_exp_other)   // -1: we need to wait until the other side has init'd
	{
		CompleteInit(m_g_exp_other);
	}
}

void Person::CompleteInit(int gx)
{
	m_g_exp_other = gx;
	m_dh_key = modexp(m_g_exp_other, m_secret, m_p);
	ComputeAes();
}

void Person::ComputeAes()
{
	// This assert fires when M tampers with our protocol.
	// It seems like this would make it obvious that something was wrong.
	// Assert(m_dh_key > 0, "DH==0 in ComputeAes");
	if (m_dh_key == 0)
	{
		std::cout << "Warning: Network tampering detected by " << m_name << std::endl;
	}

	m_aes_key.clear();
	byte result[kDigestSize + 1];
	byte buf[sizeof(int) + 1];
	sprintf_s(reinterpret_cast<char*>(buf), _countof(buf), "%4d", m_dh_key);
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


// Implementation of class Attacker

Attacker::Attacker(const std::string& name)
	:m_name(name)
{
}


void Attacker::InterceptInit(Person& from, Person& to, int p, int g)
{
	std::cout << "Attacker \"" << m_name << "\" is listening!" << std::endl;

	// Note: in comments here, "from" = A, "to" = B

	// Hold onto the original correct values for p and g
	m_p = p;
	m_g = g;
	from.Init(p, g);  // These are always set correctly at A's end - not under M's control

	switch (m_nAttack)
	{

	case 1:
	{
		// Attack 1 - Ch5-34
		// ==> Instead of passing on ga and gb, send p
		std::cout << "Attacker is substituting p for ga, gb" << std::endl;

		to.Init(m_p, m_g, m_p);
		from.CompleteInit(m_p);
		//
		// g^a = p   g^b = p
		// g^ab = p^b  g^ba = p^a
		// g^ab mod p = g^ba mod p = 0
		// At this point we can conclude:
		//   - The common DH Key computed by A and B will be 0
		//   - The common AES key computed by A and B will be SHA1(0)
		// So we just compute SHA1(0) and hold onto it
		m_dh_key = 0;
		ComputeAes();
	}
	break;

	case 2:
	{
		// Attack 2 - Ch5-35
		// ==> set g = 1
		std::cout << "Attacker is substituting 1 for g" << std::endl;
		// g^a = 1  g^b = 1
		// g^ab =1 g^ba = 1
		// g^ab mod p = g^ba mod p = 1
		// At this point we can conclude:
		//   - The common DH Key computed by A and B will be 1
		//   - The common AES key computed by A and B will be SHA1(1)
		// So we just compute SHA1(1) and hold onto it
		to.Init(m_p, 1, 1);
		from.CompleteInit(1);
		m_dh_key = 1;
		ComputeAes();
	}
	break;

	case 3:
	{
		// Attack 3 - Ch5-35 
		// ==> set g = p
		std::cout << "Attacker is substituting p for g" << std::endl;
		to.Init(m_p, m_p, 0);
		// "To" responds with its gx so "From" can complete its initialization
		from.CompleteInit(to.m_g_exp_own);  // should be 0, but we could set explicitly

											// g^a = p^a   g^b = p^b
											// g^a mod p = g^b mod p = 0
											// g^ab = p^ab g^ba = p^ba
											// g^ab mod p = g^ba mod p = 0
											// At this point we can conclude:
											//   - The common DH Key computed by A and B will be 0
											//   - The common AES key computed by A and B will be SHA1(0)
											// So we just compute SHA1(0) and hold onto it
		m_dh_key = 0;
		ComputeAes();
	}
	break;

	case 4:
	{
		// Attack 4 - Ch5-35 
		// ==> set g = p-1
		std::cout << "Attacker is substituting p-1 for g" << std::endl;

		// We need to compute g^x mod p for a in [0, p) unknown
		// (p-1) ^ 1 mod p = p-1
		// (p-1) ^ 2 mod p = (p^2 - 2p + 1) mod p = p^2 mod p - 2p mod p + 1 mod p = 1 
		// (p-1) ^ 3 mod p = (p-1)(p-1)^2 mod p = p-1
		// (p-1) ^ 4 mod p = (p-1)^2(p-1)^2 mod p = 1 mod p = 1
		// So:
		//    g^x mod p = { p-1  for x odd,  1 for x even } 
		//
		// Pass (g^a mod p) = 1 to B as if we knew a were even
		// Since the product a*b is even if a is even, we know
		// B will compute g^ab mod p = 1, independent of the choice of b.
		// Then we complete the deception by passing back (g^b mod p) = 1
		// to A, so that A will compute g^ab mod p = 1 independent of a.

		to.Init(m_p, m_p - 1, 1);
		// "To" responds with its gx so "From" can complete its initialization
		from.CompleteInit(1);

		//   - The common DH Key computed by A and B will be 1
		//   - The common AES key computed by A and B will be SHA1(1)
		// So we just compute SHA1(1) and hold onto it
		m_dh_key = 1;
		ComputeAes();
	}
	break;
	case 0:
	default:
	{
		// Pass-through case, no alteration or examination of the message
		to.Init(from.m_p, from.m_g, from.m_g_exp_own);
		// B responds with its gx so A can complete its initialization
		from.CompleteInit(to.m_g_exp_own);
	}
	break;

	}

}

void Attacker::InterceptMsg(Person& from, Person& to, const byte_string& msg)
{
	std::cout << "Attacker passing along message from " << from.m_name << " to " << to.m_name << std::endl;

	from.SendMsg(to, msg);
	if (m_nAttack != 0)
	{
		ExamineMsg(to.m_recv_msg_encr);
	}

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
	byte result[kDigestSize + 1];
	byte buf[sizeof(int) + 1];
	sprintf_s(reinterpret_cast<char *>(buf), _countof(buf), "%4d", m_dh_key);
	SHA1(result, buf, sizeof(int));
	for (size_t ii = 0; ii < Person::c_kAESblockSz; ++ii)
	{
		m_aes_key += result[ii];
	}
}
