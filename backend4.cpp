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

	switch (nChallenge)
	{
	case 25:
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
	break;

	case 26:
	{
		m_pAes = new Aes(m_blockSize * 8);
		m_pAes->SetMode(Aes::CTR);
		m_pAes->SetKey(m_blockSize);		// Generate a random key
	}
	break;

	default:
		break;
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

void Backend::Oracle4::EnterQuery(const byte_string& inputStr)
{
	static const byte_string preStr = reinterpret_cast<byte*>("comment1=cooking%20MCs;userdata=");
	static const byte_string postStr = reinterpret_cast<byte*>(";comment2=%20like%20a%20pound%20of%20bacon");

	if (!m_pAes) return;

	// Check input string for ';' or '='. If the user enters these, reject the query.
	const byte* pBytes = inputStr.c_str();
	size_t cnt = inputStr.length();
	while (cnt > 0)
	{
		if ((*pBytes == '=') || (*pBytes == ';')) return;
		++pBytes;
		--cnt;
	}

	// Form pre str + user input + post str
	byte_string s = preStr;
	s.append(inputStr);
	s.append(postStr);

	m_pEncryptedDataSz = s.length();
	m_pEncryptedData = (new byte[m_pEncryptedDataSz]);

	// Encrypt and store the string
	m_pAes->ResetStream();
	m_pAes->EncryptStream(s.c_str(), s.length(), m_pEncryptedData, m_pEncryptedDataSz);
}

bool Backend::Oracle4::QueryAdmin()
{
	// Check whether the query string contains the magic sequence
	static const byte* pAdminStr = reinterpret_cast<byte*>(";admin=true;");

	// Decrypt the query string
	// Assumption - decrypted data size is no bigger than encrypted data size!
	std::unique_ptr<byte[]> pDb(new byte[m_pEncryptedDataSz + 1]);
	m_pAes->ResetStream();
	m_pAes->DecryptStream(m_pEncryptedData, m_pEncryptedDataSz, pDb.get(), m_pEncryptedDataSz);
	byte* pBytes = pDb.get();
	pBytes[m_pEncryptedDataSz] = '\0';

	// Return whether the user has admin rights based on the contents of the string
	byte_string s(pBytes);
	return (s.find(pAdminStr) != byte_string::npos);
}

// The oracle exposes setting encrypted data directly (for Challenge 26).
void Backend::Oracle4::SetEncryptedData(const byte_string& encryptData)
{
	if (m_pEncryptedData)
	{
		delete m_pEncryptedData;
		m_pEncryptedData = nullptr;
		m_pEncryptedDataSz = 0;
	}

	m_pEncryptedDataSz = encryptData.length();
	m_pEncryptedData = new byte[m_pEncryptedDataSz];
	io_utils::byteCopy(m_pEncryptedData, m_pEncryptedDataSz, encryptData.c_str(), m_pEncryptedDataSz);
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

