#pragma once

#include <string>
#include "utils.h"

class Person {
public:
	Person(const std::string& name);
	~Person() {}

	void Init(int p, int g, int gx = -1);
	void CompleteInit(int gx);
	void ComputeAes();
	void SendMsg(Person& to, const byte_string& msg, bool bIncludePrev = false);
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
	int m_nAttack{ 0 };
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

