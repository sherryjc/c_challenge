#pragma once

#include "stdafx.h"

typedef unsigned char byte;
typedef int word4;    // assuming sizeof(int) = 4; handle this 

typedef enum {
	BINARY,
	BASE64,
	HEX,
	ASCII,
	UNICODE,
	UTF_8,
	UTF_16LE
} FileType;

using upByteArr = std::unique_ptr<byte[]>;
using upCharArr = std::unique_ptr<char[]>;

namespace io_utils {

	upByteArr readBinFile(const char* pFileName, size_t& outCnt);
	upCharArr readTextFile(const char* pFileName, size_t& outCnt);
	upCharArr readTextFileStripCRLF(const char* pFileName, size_t& outCnt);
	size_t writeBinFile(const char* pFileName, const byte* pBuffer, size_t cch);
	size_t writeTextFile(const char* pFileName, const char* pBuffer, size_t cch, bool bRaw=false);

	upCharArr stripCRLF(const char* pCharBuf, size_t inCnt, size_t& strippedCnt);

	void logError(const char* str);
}

namespace dbg_utils {
	void displayBytes(const char* pIntroStr, const byte* pBytes, size_t cnt);

}

namespace crypto_utils {

	upByteArr hexToBin(const char* pHexBuf, size_t inCnt, size_t& outCnt);
	upCharArr binToHex(const byte* pBuf, size_t inCnt, size_t& outCnt);
	upCharArr binToBase64(const byte* pBuf, size_t inCnt, size_t& outCnt);
	upByteArr base64ToBin(const char* pB64Buf, size_t inCnt, size_t& outCnt);
	upCharArr binToTxtANSI(const byte* pBuf, size_t inCnt, size_t& outCnt);

	bool convHexToBase64(const char* pHexFile, const char* pBase64File);
	bool convBase64ToHex(const char* pBase64File, const char* pHexFile);

	int rateANSI(byte* pByteArray, size_t cnt);
	upCharArr checkSingleByteXORAnsi(const byte* pInBuf, const size_t inCnt, unsigned& key, int& o_score);
	upCharArr checkSingleByteXORAnsiH(const char* pHexBuf, const size_t inCnt, unsigned& key, int& o_score);

	upByteArr encryptRepeatingKey(const std::string& text, const std::string& key, size_t& outCnt);
	upCharArr decryptRepeatingKey(const byte* pBuf, const size_t bufCnt, const byte* pKey, const size_t keyLen);

	unsigned countBits(byte x);
	unsigned hammingDistance(byte x, byte y);
	unsigned hammingDistance(const byte* pX, size_t lenX, const byte* pY, size_t lenY);

	using KeyLengthRatings = std::unordered_map<unsigned, float>;
	unsigned getKeyLengthRatings(const byte* pBytes, unsigned stKeyLen, unsigned endKeyLen, KeyLengthRatings& keyLengthRatings);
	upCharArr decodeUsingFixedKeyLength(const byte* pBinBuf, size_t binCnt, byte* pKey, size_t keyLength);

}
