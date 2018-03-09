#pragma once


#include <string>
#include <memory>
#include "utils.h"
#include "aes.h"

namespace Backend {

	// Set 2, Challenge 11
	void EncryptionOracle_2_11(const std::string& inStr, byte_string& outStr);

	// Set 2, Challenge 12
	std::unique_ptr< byte[] > EncryptionOracle_2_12(const byte* pInput, size_t len, size_t& outLen);

	// Set 2, Challenge 13
	byte_string EncryptionOracle_2_13(const std::string& emailAddr);
	bool Add_User_2_13(const byte_string& encryptedRec);

	// Set 2, Challenge 14
	std::unique_ptr< byte[] > EncryptionOracle_2_14(const byte* pInput, size_t len, size_t& outLen);

	// Set 2, Challenge 16
	std::unique_ptr< byte[] >  EncryptionOracle_2_16(const std::string& strInput, size_t& outLen);
	std::string DecryptionOracle_2_16(const byte* pInput, size_t len);

	// Set 3, Challenge 17
	void EncryptionOracle_3_17(byte_string& ciphertext, byte_string& iv);
	bool DecryptionOracle_3_17(const byte_string& ciphertext, const byte_string& iv);
	// Debug only - wouldn't expose this to the user
	void DumpAllOracle_3_17();

	// Set 4
	class Oracle4 {
	public:
		static Oracle4* Get(int nChallenge);
		void EditEncryptedStream(size_t offset, byte_string replacement);
		size_t GetEncryptedDataSize();
		void GetEncryptedData(byte* pBuffer, size_t bufSz);

		// Dump the database in plain text for testing. Obviously this would not be part of the real Oracle!
		void DumpDatabase();

	private:
		Oracle4();
		~Oracle4();
		void _Init(int nChallenge);
		// data members
		Aes* m_pAes = nullptr;
		const size_t m_blockSize = 16;
		byte* m_pEncryptedData = nullptr;
		size_t m_pEncryptedDataSz = 0;
	};
}
