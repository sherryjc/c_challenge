#pragma once

#include "stdafx.h"

typedef unsigned char byte;

namespace io_utils {

	enum _encoding {
		IO_UTILS_UNICODE,
		IO_UTILS_UTF_8,
		IO_UTILS_UTF_16LE
	};

	std::unique_ptr<byte[]> readBinFile(const char* pFileName, size_t& outCnt);
	std::unique_ptr<char[]> readTextFile(const char* pFileName, size_t& outCnt);
	std::unique_ptr<char[]> readTextFileStripCRLF(const char* pFileName, size_t& outCnt);
	size_t writeBinFile(const char* pFileName, const char* pBuffer, size_t cch);
	size_t writeTextFile(const char* pFileName, const char* pBuffer, size_t cch, bool bRaw=false);

	std::unique_ptr<char[]> stripCRLF(const char* pCharBuf, size_t inCnt, size_t& strippedCnt);

	void logError(const char* str);
}

namespace dbg_utils {
	void displayBytes(const char* pIntroStr, const byte* pBytes, size_t cnt);

}

namespace crypto_utils {

	std::unique_ptr<byte[]> hexToBin(const char* pHexBuf, size_t inCnt, size_t& outCnt);
	std::unique_ptr<char[]> binToHex(const byte* pBuf, size_t inCnt, size_t& outCnt);
	std::unique_ptr<char[]> binToBase64(const byte* pBuf, size_t inCnt, size_t& outCnt);
	std::unique_ptr<byte[]> base64ToBin(const char* pB64Buf, size_t inCnt, size_t& outCnt);
	std::unique_ptr<char[]> binToTxtANSI(const byte* pBuf, size_t inCnt, size_t& outCnt);

	bool convHexToBase64(const char* pHexFile, const char* pBase64File);
	bool convBase64ToHex(const char* pBase64File, const char* pHexFile);

	int rateANSI(byte* pByteArray, size_t cnt);
	std::unique_ptr<char[]> checkSingleByteXORAnsi(const byte* pInBuf, const size_t inCnt, unsigned& key, int& o_score);
	std::unique_ptr<char[]> checkSingleByteXORAnsiH(const char* pHexBuf, const size_t inCnt, unsigned& key, int& o_score);

	std::unique_ptr<byte[]> encryptRepeatingKey(const std::string& text, const std::string& key, size_t& outCnt);
	std::unique_ptr<char[]> decryptRepeatingKey(const byte* pBuf, const size_t bufCnt, const byte* pKey, const size_t keyLen);

	unsigned countBits(byte x);
	unsigned hammingDistance(byte x, byte y);
	unsigned hammingDistance(const byte* pX, size_t lenX, const byte* pY, size_t lenY);

	using KeyLengthRatings = std::unordered_map<unsigned, float>;
	unsigned getKeyLengthRatings(const byte* pBytes, unsigned stKeyLen, unsigned endKeyLen, KeyLengthRatings& keyLengthRatings);
	std::unique_ptr<char[]> decodeUsingFixedKeyLength(const byte* pBinBuf, size_t binCnt, byte* pKey, size_t keyLength);

	std::unique_ptr<char[]> decryptAes128Ecb(const byte* pBuf, const size_t bufCnt, const byte* pKey, const size_t keyLen);

}
