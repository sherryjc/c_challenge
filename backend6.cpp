
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

bool Backend::Oracle6::Encrypt(const byte_string& plaintxt, byte_string& ciphertxt)
{
	if (!m_pRSA) return false;

	return m_pRSA->Encrypt(plaintxt, ciphertxt);
}
