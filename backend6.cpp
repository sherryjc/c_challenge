
#include "backend.h"
#include "rsa.h"

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

