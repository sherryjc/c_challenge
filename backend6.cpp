
#include "backend.h"
#include "rsa.h"
#include "sha256.h"

static Backend::Oracle6* s_pOnlyOracle6 = nullptr;

//static 
Backend::Oracle6* Backend::Oracle6::Get(int nChallenge)
{
	if (!s_pOnlyOracle6)
	{
		s_pOnlyOracle6 = new Backend::Oracle6();
	}
	s_pOnlyOracle6->_Init(nChallenge);
	return s_pOnlyOracle6;
}

Backend::Oracle6::Oracle6()
{
}

Backend::Oracle6::~Oracle6()
{
}

void Backend::Oracle6::_Init(int nChallenge)
{

	switch (nChallenge)
	{
	case 41:
	{
		_InitRSA();
	}
	break;

	default:
		break;
	}

}

void Backend::Oracle6::_InitRSA()
{
	m_pRSA = new JRSA();
}

bool Backend::Oracle6::EncryptBlock(const byte_string& plaintxt, byte_string& ciphertxt, size_t& cnt)
{
	if (!m_pRSA) return false;

	return m_pRSA->EncryptBlock(plaintxt, ciphertxt, cnt);
}

bool Backend::Oracle6::DecryptBlock(const byte_string& ciphertxt, byte_string& plaintxt)
{
	if (!m_pRSA) return false;

	byte hash_out[SHA256_BLOCK_SIZE+1];
	SHA256(ciphertxt.c_str(), ciphertxt.length(), hash_out, _countof(hash_out));
	hash_out[SHA256_BLOCK_SIZE] = '\0';
	byte_string hash_str(hash_out);

	int expiration = CheckCache(hash_str);

	// For now, no check of expiration. If it's in the cache already, refuse to provide the decryption.
	if (0 != expiration) return false;

	AddCache(hash_str);
	return m_pRSA->DecryptBlock(ciphertxt, plaintxt);
}

bool Backend::Oracle6::EncryptHex(const byte_string& plaintxt, byte_string& ctHex)
{
	if (!m_pRSA) return false;

	return m_pRSA->EncryptHex(plaintxt, ctHex);
}

bool Backend::Oracle6::DecryptHex(const byte_string& ctHex, byte_string& plaintxt)
{
	if (!m_pRSA) return false;

	return m_pRSA->DecryptHex(ctHex, plaintxt);
}

int Backend::Oracle6::CheckCache(const byte_string& key)
{
	auto search = m_cipherCache.find(key);
	if (search != m_cipherCache.end())
	{
		return search->second;
	}
	return 0;
}

void Backend::Oracle6::AddCache(const byte_string& key)
{
	static int s_currentTime = 34745;
	m_cipherCache.insert({key, s_currentTime++});
}

void Backend::Oracle6::PublicKey(BIGNUM** ppE, BIGNUM** ppN)
{
	if (!m_pRSA) return;

	m_pRSA->PublicKey(ppE, ppN);
}

