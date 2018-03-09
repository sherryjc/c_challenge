#include "backend.h"
#include <unordered_map>
#include <iostream>
#include "aes.h"
#include "utils.h"

using namespace crypto_utils;
using namespace io_utils;

//////////////////////////////////////////////////////////////////////////
//
// Back end functions (Oracles, etc.) for Set 4
//
//////////////////////////////////////////////////////////////////////////

static Backend::Oracle4* s_pOnlyOracle4 = nullptr;

//static 
Backend::Oracle4* Backend::Oracle4::Get(int nChallenge)
{
	if (!s_pOnlyOracle4)
	{
		s_pOnlyOracle4 = new Backend::Oracle4();
	}
	s_pOnlyOracle4->_Init(nChallenge);
	return s_pOnlyOracle4;
}

Backend::Oracle4::Oracle4()
{
	// All initialization was in the header file
}

Backend::Oracle4::~Oracle4()
{
	_Init(-1);
}

void Backend::Oracle4::_Init(int nChallenge)
{
	if (m_pAes)
	{
		delete m_pAes;
		m_pAes = nullptr;
	}

	if (m_pEncryptedData)
	{
		delete m_pEncryptedData;
		m_pEncryptedData = nullptr;
		m_pEncryptedDataSz = 0;
	}

	if (nChallenge == 25)
	{
		// same input data as Set1Ch7
		static const char* pInFile = "./data/set4/challenge25/input.b64";
		static const byte bKey[] = "YELLOW SUBMARINE";


		// Set the current contents of the oracle to the recovered plaintext from the above file
		Aes aes2(128);
		aes2.SetKey(bKey, _countof(bKey) - 1);
		aes2.Read(pInFile, FileType::BASE64);
		aes2.Decrypt();
		byte_string inputStr;
		aes2.ResultStr(inputStr);

		// Now encrypt the string with our session key and store it in the Oracle's "database"
		m_pAes = new Aes(m_blockSize * 8);
		m_pAes->SetMode(Aes::CTR);
		m_pAes->SetKey(m_blockSize);		// Generate a random key
		m_pEncryptedDataSz = inputStr.length();
		m_pEncryptedData = (new byte[m_pEncryptedDataSz]);
		m_pAes->ResetStream();
		m_pAes->EncryptStream(inputStr.c_str(), m_pEncryptedDataSz, m_pEncryptedData, m_pEncryptedDataSz);
	}
}

void Backend::Oracle4::EditEncryptedStream(size_t offset, byte_string replacement)
{
	if (!m_pAes) return;

	m_pAes->ReplaceStreamBytes(m_pEncryptedData, m_pEncryptedDataSz, offset, replacement);

}



size_t Backend::Oracle4::GetEncryptedDataSize()
{
	return m_pEncryptedDataSz;
}

void Backend::Oracle4::GetEncryptedData(byte* pBuffer, size_t bufSz)
{
	if (bufSz < m_pEncryptedDataSz) return;

	io_utils::byteCopy(pBuffer, bufSz, m_pEncryptedData, m_pEncryptedDataSz);

}

// Test function - remove from production code!
void Backend::Oracle4::DumpDatabase()
{
	// Assumption - decrypted data size is no bigger than encrypted data size!
	std::unique_ptr<byte[]> pDb(new byte[m_pEncryptedDataSz + 1]);
	m_pAes->ResetStream();
	m_pAes->DecryptStream(m_pEncryptedData, m_pEncryptedDataSz, pDb.get(), m_pEncryptedDataSz);
	byte* pDisplay = pDb.get();
	pDisplay[m_pEncryptedDataSz] = '\0';
	std::cout << pDisplay << std::endl;
}
