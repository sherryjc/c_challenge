#pragma once

#include "utils.h"

class Aes
{
public:
	Aes(size_t nBlockSizeBits);
	~Aes();

	size_t Read(const char* pFilename, FileType fType);

	size_t Write(const char* pFilename, FileType fType);

	void SetKey(const byte* pKey, const size_t keyLen);
	void Encrypt();
	void Decrypt();

private:
	size_t ReadBin(const char* pFilename);
	size_t ReadAscii(const char* pFilename);
	size_t ReadBase64(const char* pFilename);

	size_t WriteBin(const char* pFilename);

	void InitOutput(size_t sz, size_t szPadded);

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

	size_t m_nBlockSizeBits;
	size_t m_nBlockSize;
	size_t m_nRounds;
	size_t m_nBlockColumns;
	size_t m_nKeySize;
	size_t m_nExpandedKeySize;
	size_t m_nInputSize;
	size_t m_nInputSizePadded;
	size_t m_nOutputSize;
	size_t m_nOutputSizePadded;

	std::unique_ptr<byte[]>	m_pInput;
	std::unique_ptr<byte[]>	m_pOutput;
	std::unique_ptr<byte[]>	m_pKey;
	std::unique_ptr<byte[]>	m_pExpandedKey;
};