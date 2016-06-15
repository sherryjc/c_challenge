#pragma once

#include "stdafx.h"

typedef unsigned char byte;

namespace io_utils {

	enum _encoding {
		IO_UTILS_UNICODE,
		IO_UTILS_UTF_8,
		IO_UTILS_UTF_16LE
	};

	std::unique_ptr<byte[]> readBinFile(const char* pFileName, size_t& outSz);
	std::unique_ptr<char[]> readTextFileA(const char* pFileName);
	size_t writeBinFile(const char* pFileName, const char* pBuffer, size_t cch);
	size_t writeTextFileA(const char* pFileName, const char* pBuffer, size_t cch, bool bRaw=false);

	void logError(const char* str);
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
	std::unique_ptr<char[]> checkSingleByteXORAnsi(const byte* pInBuf, const size_t inCnt, int& o_score);
	std::unique_ptr<char[]> checkSingleByteXORAnsi(const char* pHexBuf, const size_t inCnt, int& o_score);
}
