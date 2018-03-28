#pragma once

#include "stdafx.h"

using byte = unsigned char;
using byte_string = std::basic_string<byte>;

class N;

//typedef unsigned char byte;
typedef int word4;    // assuming sizeof(int) = 4; handle this 

typedef enum  {
	BINARY,
	BASE64,
	HEX,
	ASCII,
	UNICODE,
	UTF_8,
	UTF_16LE
} FileType;

typedef enum {
	PKCS_7,
	NULLS
} PaddingScheme;

using upByteArr = std::unique_ptr<byte[]>;
using upCharArr = std::unique_ptr<char[]>;

namespace io_utils {

	upByteArr readBinFile(const char* pFileName, size_t& outCnt, size_t blockSize=0, PaddingScheme padSch=PaddingScheme::PKCS_7);
	upCharArr readTextFile(const char* pFileName, size_t& outCnt);
	upCharArr readTextFileStripCRLF(const char* pFileName, size_t& outCnt);
	size_t writeBinFile(const char* pFileName, const byte* pBuffer, size_t cch);
	size_t writeTextFile(const char* pFileName, const char* pBuffer, size_t cch, bool bRaw=false);

	upCharArr stripCRLF(const char* pCharBuf, size_t inCnt, size_t& strippedCnt);
	void separateStrings(std::vector<std::string>&vec, const char* pTxt, size_t charCnt);

	byte* byteCopy(byte* pDst, size_t szDst, const byte* pSrc, size_t szSrc);
	byte* byteCopyRepeated(byte* pDst, size_t szDst, const char c, size_t szSrc);

	bool byteCompare(const byte* p1, const byte* p2, size_t n);
	bool byteCompare(const byte_string& s1, const byte_string& s2);
	size_t nBytesCompare(const byte* p1, const byte* p2, size_t nMax);

	// Big-endian byte strings <-> ints
	void int64ToBytesBE(int64_t paramInt, byte* pBytes, size_t byteCnt);
	void BytesBEToUInt64(const byte* pBytes, size_t byteCnt, uint64_t& result);
	void BytesBEToInt32(const byte* pBytes, size_t byteCnt, int32_t& result);
	void int32ToBytesBE(int32_t paramInt, byte* pBytes, size_t byteCnt);

		// Little-endian
	void int64ToBytesLE(int64_t paramInt, byte* pBytes, size_t byteCnt);

	bool GetCurrentTimeUnixFmt(int64_t *pUnixTime);

	void logError(const char* str);
}

namespace dbg_utils {
	void displayBytes(const char* pIntroStr, const byte* pBytes, size_t cnt);
	void displayHex(const byte* pBytes, size_t cnt);
	void displayHex(const byte_string& str);
	void formatHex(std::string& deststr,  const byte* pBytes, size_t cnt);
	void formatHex(std::string& deststr, const byte_string& str);
	void displayByteStrAsCStr(const byte_string& str);
}

namespace crypto_utils {
	
	upByteArr hexToBin(const char* pHexBuf, size_t inCnt, size_t& outCnt);
	upCharArr binToHex(const byte* pBuf, size_t inCnt, size_t& outCnt);
	upCharArr binToBase64(const byte* pBuf, size_t inCnt, size_t& outCnt);
	upByteArr base64ToBin(const char* pB64Buf, size_t inCnt, size_t& outCnt, size_t blockSize = 0, PaddingScheme padSch=PaddingScheme::PKCS_7);
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

	bool checkDuplicateBlocks(const std::string& str, size_t blockSize);
	int getLongestRepeatedPattern(const byte* pBytes, size_t nBytes);
	void xorBlock(byte* pDest, const byte* pIn1, const byte* pIn2, size_t cnt);

	bool getRandomBool();
	byte getRandomByte();
	unsigned int getRandomNumber();
	byte_string getRandomBytes(const size_t nMaxLen);

	void generateKey(byte* pKey, size_t len);

	size_t paddedSize(size_t inpSz, size_t blkSz);
	bool stripPKCS7Padding(const std::string& str, std::string& outStr, size_t blockSize);
}

namespace math_utils
{
	int modexp(int b, int e, int p);   // b^e mod p    (b=base, e=exponent)

	// returns greatest common divisor between a and b
	int gcd(int a, int b);

	// returns greatest common divisor between a and b, as well as lambda and mu such that
	// lambda * a + mu * b = gcd(a,b)
	int extended_gcd(int a, int b, int& lambda, int& mu);

	// Returns true if 'a' has an inverse mod m, false otherwise.
	// The inverse is returned in the argument 'a_inv' if the inverse exists.
	bool invmod(int a, int m, int& a_inv);

	// Check whether a and a_inv are inverses mod m
	bool checkInvMod(int a, int a_inv, int m);

	bool byteBufToULL(const byte* pBytes, size_t nBytes, unsigned long long& ull);   // Not implemented yet
}


