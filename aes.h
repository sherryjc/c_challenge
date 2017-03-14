#pragma once
#ifndef AES_H
#define AES_H

#include "utils.h"

class Aes
{
public:
	enum _mode {
		AES_UNKNOWN,
		ECB,			// Electronic Codebook 
		CBC				// Cipher Block Chaining
	};

	Aes(size_t nBlockSizeBits, int mode=Aes::ECB);  // ECB not secure, but the default due to backwards test compatibility
	~Aes();

	size_t Read(const char* pFilename, FileType fType);

	size_t Write(const char* pFilename, FileType fType);

	// Set key to known value
	void SetKey(const byte* pKey, const size_t keyLen);
	// Set key to randomly generated value
	void SetKey(const size_t keyLen);

	void SetMode(int mode);
	int Mode() const;

	void Encrypt();
	void Decrypt();

	const byte* Result(size_t& len);

	// Specific to various exercises (numbered _Set_Challenge)
	void EncryptionOracle_2_11(const char* pInput, size_t len);
	int DetectionOracle_2_11(const byte* pInput, size_t len);

	void EncryptionOracle_2_12(const char* pInput, size_t len, const char* pFilename);
	int DetectionOracle_2_12(const byte* pInput, size_t len);


private:
	size_t ReadBin(const char* pFilename);
	size_t ReadAscii(const char* pFilename);
	size_t ReadBase64(const char* pFilename);

	size_t WriteBin(const char* pFilename);
	size_t WriteHex(const char* pFilename);

	void InitOutput(size_t sz);
	enum _iv_type {
		ALL_ZEROES,
		RANDOM
	};
	void SetInitializationVector(int ivType);

	byte GetSBoxValue(byte num);
	byte GetSBoxInvert(byte num);
	byte GetRconValue(byte num);
	void Rotate(byte *word);
	void Core(byte *word, byte iteration);
	void ExpandKey();
	void AddRoundKey(byte* pState, const byte* pRoundKey);
	void ShiftRowLeft(byte* pState);
	void ShiftRowRight(byte* pState);

	void MixColumn(byte* pState);
	void MixColumnInvert(byte* pState);

	void EncryptRound(byte* pState, const byte* pRoundKey, bool bFinal = false);
	void DecryptRound(byte* pState, const byte* pRoundKey, bool bFinal = false);
	void EncryptBlock(byte* pOutput, const byte* pInput);
	void DecryptBlock(byte* pOutput, const byte* pInput);
	
	static byte Mult(byte a, byte b);
	static void MxVec4(byte* v);
	static void MIxVec4(byte* v);
	
	// Modifies input according to internal rules for the
	// "specific exercise" functions above
	void ModifyInput1(const char* pInput, size_t inputLen);	

// data members
	size_t m_nBlockSizeBits;
	size_t m_nBlockSize;
	size_t m_nRounds;
	size_t m_nBlockColumns;
	size_t m_nKeySize;
	size_t m_nExpandedKeySize;
	size_t m_nInputSize;
	size_t m_nOutputSize;
	
	std::unique_ptr<byte[]>	m_pInput;
	std::unique_ptr<byte[]>	m_pOutput;
	std::unique_ptr<byte[]>	m_pKey;
	std::unique_ptr<byte[]>	m_pExpandedKey;
	std::unique_ptr<byte[]>	m_pInitVec;

	int m_mode;
};

#endif // AES_H
