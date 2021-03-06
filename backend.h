#pragma once


#include <string>
#include <memory>
#include <openssl/bn.h>
#include "utils.h"
#include "aes.h"
#include "rsa.h"

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
		void SetEncryptedData(const byte_string& encryptData);

		void GetCiphertext(byte_string& ciphertxt);
		void SetCiphertext(const byte_string& ciphertxt);
		void SetRawCiphertext(const byte* pBytes, size_t len);
		void GetPlaintext(byte_string& plaintext);
		void SetPlaintext(const byte_string& plainText);
		void Encrypt_Ch27();
		void Validate_Ch27(byte_string& errorTxt);

		void EnterQuery(const byte_string& inputStr);
		bool QueryAdmin();

		// Dump the database in plain text for testing. Obviously this would not be part of the real Oracle!
		void DumpDatabase();

	private:
		Oracle4();
		~Oracle4();
		void _Init(int nChallenge);
		// data members
		Aes* m_pAes = nullptr;
		const size_t m_blockSize = 16;

		byte_string m_ciphertext;
		byte_string m_plaintext;
		byte_string m_key;

		byte*  m_pRawCiphertext = nullptr;    // TODO: because I am having trouble getting 0's into a byte_string w/o it terminating the string
		size_t m_nRawCTSz = 0;
		// TODO - refactor, get rid of these 
		byte* m_pEncryptedData = nullptr;
		size_t m_pEncryptedDataSz = 0;
	};

	void GetHash4_29(const byte_string& input, byte* pHash, size_t hashLen); // The Oracle is kind enough to give us back hashes
	bool Authorization4_29(const byte_string& request, const byte* pHash, size_t hashLen);  


	// Set 6
	class Oracle6 {
	public:
		static Oracle6* Get(int nChallenge);
		bool EncryptBlock(const byte_string& plaintxt, byte_string& ciphertxt, size_t& cnt);
		bool DecryptBlock(const byte_string& ciphertxt, byte_string& plaintxt);
		bool EncryptHex(const byte_string& plaintxt, byte_string& ctHex);
		bool DecryptHex(const byte_string& ctHex, byte_string& plaintxt);

		void PublicKey(BIGNUM** ppE, BIGNUM** ppN);

	private:
		Oracle6();
		~Oracle6();
		void _Init(int nChallenge);
		void _InitRSA();

		int CheckCache(const byte_string& ct);   // returns 0 if not found, otherwise expiration time
		void AddCache(const byte_string& ct);

		JRSA* m_pRSA{ nullptr };

		std::unordered_map<byte_string, int>  m_cipherCache;  // hash of ciphertexts -> time (not used)
	};

}
