
#define _CRT_RAND_S
#include <stdio.h>
#include "utils.h"
#include <unordered_set>
#include <stdlib.h>
#include <vector>
#include <sstream>
#include <iosfwd>
#include <iostream>
#include <iomanip>


static byte _hexByte(char c)
{
	// Convert 0-9a-f or A-F to single-byte numeric value
	if (c >= '0' && c <= '9') {
		return static_cast<byte>(c - '0');
	}
	if (c >= 'A' && c <= 'F') {
		return static_cast<byte>(c - 'A' + 10);
	}
	if (c >= 'a' && c <= 'f') {
		return static_cast<byte>(c - 'a' + 10);
	}
	return 0xff;
}

static char _byteToHexDigit(byte b)
{
	// Convert binary digit to hex ANSI character
	if (b > 0xf) {
		return '?';
	}
	if (b >= 0xa) {
		return b - 0xa + 'a';
	}
	return b + '0';
}

void io_utils::logError(const char* str)
{
	fprintf(stderr, "Error: %s\n", str);
}

upByteArr io_utils::readBinFile(const char* pFileName, size_t& outSz, size_t blockSize, PaddingScheme padSch)
{
	outSz = 0;
	FILE* pFile = fopen(pFileName, "rb");
	if (nullptr == pFile) { 
		logError("fopen"); 
		return nullptr; 
	}

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	long lSize = ftell(pFile);
	rewind(pFile);

	// If a block size was provided, round up the size of the buffer allocated to the nearest multiple of that size
	size_t paddedCnt = (blockSize > 0 && lSize % blockSize) ? (lSize / blockSize + 1) * blockSize : lSize;

	// allocate memory to contain the whole file (plus padding bytes if requested)
	auto pBuffer = upByteArr(new byte[paddedCnt]);
	if (nullptr == pBuffer) { 
		logError("new"); 
		fclose(pFile);
		return nullptr; 
	}

	auto destBuf = pBuffer.get();
	// copy the file into the buffer:
	size_t itemsRead = fread(destBuf, 1, lSize, pFile);
	if (itemsRead != lSize) { 
		logError("fread"); 
	}

	// Add padding bytes if necessary
	byte padByte = (padSch == PaddingScheme::PKCS_7) ? static_cast<byte>(paddedCnt-lSize) : 0;
	for (size_t i = lSize; i < paddedCnt; ++i) {
		destBuf[i] = padByte;
	}

	outSz = paddedCnt;
	fclose(pFile);
	return pBuffer;
}

upCharArr io_utils::readTextFile(const char* pFileName, size_t& outCnt)
{
	FILE * pFile = fopen(pFileName, "r");
	if (nullptr == pFile) {
		logError("fopen");
		return nullptr;
	}

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	long lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	upCharArr pBuffer = upCharArr(new char[lSize+1]);
	if (nullptr == pBuffer) {
		logError("new");
		fclose(pFile);
		return nullptr;
	}

	// copy the file into the buffer:
	size_t itemsRead = fread(pBuffer.get(), sizeof(char), lSize, pFile);
	if (itemsRead == 0) {   
		logError("fread");
	}
	pBuffer[itemsRead] = '\0';
	outCnt = itemsRead;
	fclose(pFile);
	return pBuffer;
}

upCharArr io_utils::readTextFileStripCRLF(const char* pFileName, size_t& outCnt)
{
	size_t readCnt = 0;
	upCharArr pTxt = io_utils::readTextFile(pFileName, readCnt);
	upCharArr pStrippedTxt = stripCRLF(pTxt.get(), readCnt, outCnt);
	return pStrippedTxt;
}

size_t io_utils::writeBinFile(const char* pFileName, const byte* pBuffer, size_t cch)
{
	return writeTextFile(pFileName, reinterpret_cast<const char*>(pBuffer), cch, true);
}

size_t io_utils::writeTextFile(const char* pFileName, const char* pBuffer, size_t cch, bool bRaw)
{
	FILE * pFile = fopen(pFileName, bRaw ? "wb" : "w");
	if (nullptr == pFile) {
		logError("fopen");
		return 0;
	}

	size_t itemsWritten = fwrite(pBuffer, sizeof(char), cch, pFile);
	if (itemsWritten != cch) {
		logError("fread");
	}
	fclose(pFile);
	return itemsWritten;
}


upCharArr io_utils::stripCRLF(const char* pCharBuf, size_t inCnt, size_t& strippedCnt)
{
	std::unique_ptr<char[]>pStrippedBuffer = std::unique_ptr<char[]>(new char[inCnt + 1]);
	char* pDest = pStrippedBuffer.get();
	strippedCnt = 0;
	const char* pSrc = pCharBuf;
	for (size_t i = 0; i < inCnt; i++) {
		if (*pSrc != '\n' && *pSrc != '\r') {
			*pDest++ = *pSrc;
			strippedCnt++;
		}
		pSrc++;
	}
	pDest[strippedCnt] = '\0';
	return pStrippedBuffer;
}

void io_utils::separateStrings(std::vector<std::string>&vec, const char* pTxt, size_t charCnt)
{
	size_t cnt = 0;
	std::unique_ptr<char[]>pLocal = std::unique_ptr<char[]>(new char[charCnt + 1]);
	char* pStartLocal = pLocal.get();
	char* pDest = pStartLocal;
	char* pCurrStr = pDest;
	while (cnt < charCnt) {
		if (*pTxt == '\0' || *pTxt == '\n' || *pTxt == '\r') {
			*pDest = '\0';
			std::string s = pCurrStr;
			if (s.length() > 0) {
				vec.emplace_back(s);
			}
			pDest = pStartLocal;
			pCurrStr = pDest;
		}
		else {
			*pDest++ = *pTxt;
		}
		pTxt++;
		cnt++;
	}
}

byte* io_utils::byteCopy(byte* pDst, size_t szDst, const byte* pSrc, size_t szSrc)
{
	if (szSrc > szDst) {
		return nullptr;
	}
	byte* pRet = pDst;
	for (size_t i = 0; i < szSrc; ++i) {
		*pDst++ = *pSrc++;
	}
	return pRet;
}

// This variant is useful for adding padding bytes (all of the same value)
byte* io_utils::byteCopyRepeated(byte* pDst, size_t szDst, const char c, size_t szSrc)
{
	if (szSrc > szDst) {
		return nullptr;
	}
	byte* pRet = pDst;
	for (size_t i = 0; i < szSrc; ++i) {
		*pDst++ = c;
	}
	return pRet;

}

// byte* pInp - points to an array of bytes of size inpSz
// Does what this is intended to do:
// byte_string str = p; 
// The problem with this last statement is that there may be 0x00
// values in the byte array!

void io_utils::FillByteString(byte_string& str, const byte* pInp, size_t inpSz)
{
	while (inpSz-- > 0)
	{
		str += *pInp++;
	}
}

bool io_utils::byteCompare(const byte* p1, const byte* p2, size_t n)
{
	if (!p1 || !p2 || n == 0) {
		return false;
	}

	for (size_t i = 0; i < n; ++i) {
		if (*p1++ != *p2++) {
			return false;
		}
	}
	return true;
}

bool io_utils::byteCompare(const byte_string& s1, const byte_string& s2)
{
	if (s1.length() != s2.length())
	{
		// std::cout << "Lengths differ: " << s1.length() << " != " << s2.length() << std::endl;
		return false;
	}

	return byteCompare(s1.c_str(), s2.c_str(), s1.length());
}

size_t io_utils::nBytesCompare(const byte* p1, const byte* p2, size_t nMax)
{
	if (!p1 || !p2 || nMax == 0) {
		return 0;
	}
	size_t retVal = 0;

	for (size_t i = 0; i < nMax; ++i) {
		if (*p1++ != *p2++) {
			break;
		}
		++retVal;
	}
	return retVal;
}

// Big-endian
void io_utils::int64ToBytesBE(int64_t paramInt, byte* pBytes, size_t byteCnt)
{
	if (byteCnt < 8) return;

	for (int i = 0; i < 8; ++i) {
		pBytes[7 - i] = static_cast<byte>(paramInt >> (i * 8));
	}
}

// Little-endian
void io_utils::int64ToBytesLE(int64_t paramInt, byte* pBytes, size_t byteCnt)
{
	if (byteCnt < 8) return;

	for (int i = 0; i < 8; ++i) {
		pBytes[i] = static_cast<byte>(paramInt >> (i * 8));
	}
}

void io_utils::BytesBEToInt32(const byte* pBytes, size_t byteCnt, int32_t& result)
{
	if (byteCnt < 4) return;
	result = (pBytes[0] << 24) + (pBytes[1] << 16) + (pBytes[2] << 8) + pBytes[3];
}

void io_utils::BytesBEToUInt64(const byte* pBytes, size_t byteCnt, uint64_t& result)
{
	result = 0;
	size_t nBytes = byteCnt > sizeof(uint64_t) ? sizeof(uint64_t) : byteCnt;
	for (size_t ii = 0; ii < byteCnt ; ++ii)
	{
		result = (result << 8) + *pBytes++;
	}
}

void io_utils::int32ToBytesBE(int32_t paramInt, byte* pBytes, size_t byteCnt)
{
	if (byteCnt < 4) return;

	for (int i = 0; i < 4; ++i) {
		pBytes[3 - i] = static_cast<byte>(paramInt >> (i * 8));
	}
}

bool io_utils::GetCurrentTimeUnixFmt(int64_t *pUnixTime)
{
	SYSTEMTIME	stSystemTime;
	memset(&stSystemTime, 0, sizeof(stSystemTime));
	GetSystemTime(&stSystemTime);

	FILETIME	stFileTime;

	if (SystemTimeToFileTime(&stSystemTime, &stFileTime) == FALSE) {
		return false;
	}

	// FILETIME -> UNIXTIME
	*pUnixTime = stFileTime.dwHighDateTime;
	*pUnixTime <<= 32;
	*pUnixTime += stFileTime.dwLowDateTime;
	*pUnixTime -= 116444736000000000;
	*pUnixTime /= 10000000;
	// *pUnixTime -= 32400;			// JST -> GMT from original example ?

	return true;
}

void dbg_utils::displayBytes(const char* pIntroStr, const byte* pBytes, size_t cnt)
{
	std::cout << std::endl;
	std::cout << pIntroStr;
	std::cout << std::endl;
	for (size_t i = 0; i < cnt; i++) {
		if (pBytes[i] >= 0x20 && pBytes[i] < 0x7f) {
			std::cout << pBytes[i];
		}
		else {
			std::cout << '.';
		}
	}

	std::cout << std::endl;
}

void dbg_utils::displayHex(const byte* pBytes, size_t cnt)
{
	std::cout << std::endl;
	char buf[8];
	for (size_t i = 0; i < cnt; i++) {
		if (i % 16 == 0) {
			std::cout << std::endl;
		}
		sprintf_s(buf, _countof(buf), " %02x", pBytes[i]);
		std::cout << buf;
	}
	std::cout << std::endl;
}

void dbg_utils::displayHex(const byte_string& str)
{
	dbg_utils::displayHex(str.c_str(), str.length());
}

void dbg_utils::formatHex(std::string& destStr, const byte* pBytes, size_t cnt)
{
	std::ostringstream fmtStr;
	for (size_t i = 0; i < cnt; i++) {
		fmtStr << std::setw(2) << std::hex << pBytes[i];   // C++ way to do sprintf_s " %02x"  ?? not yet working
	}
	destStr = fmtStr.str();
}

void dbg_utils::formatHex(std::string& destStr, const byte_string& str)
{
	dbg_utils::formatHex(destStr, str.c_str(), str.length());
}

void dbg_utils::displayByteStrAsCStr(const byte_string& str)
{
	// Just handles the fact that byte strings are not null terminated
	byte_string dispStr = str;
	byte* pRawBytes = const_cast<byte *>(dispStr.c_str());
	pRawBytes[dispStr.length() - 1] = '\0';
	std::cout << pRawBytes << std::endl;
}

void dbg_utils::dumpBN(const std::string& prefix, BIGNUM* pN)
{
	std::cout << prefix;
	size_t nBytes = BN_num_bytes(pN);
	std::unique_ptr<byte[]> pBin(new byte[nBytes + 1]);
	byte* p = pBin.get();
	int rc = BN_bn2bin(pN, p);
	if (0 == rc) 
	{ 
		std::cout << "Error, BN_bn2bin" << std::endl; 
		return;
	}
	p[nBytes] = '\0';
	std::cout << "Number of bytes: " << nBytes << std::endl;
	dbg_utils::displayHex(p, nBytes);
}



/*****************************************/
/*    Crypto Utils                       */
/*****************************************/

// Table of Base64 Indexes
static const char b64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Table of weighted frequency values for ANSI characters in English text
static const int vASNIEnFreqPoints[] = {
	-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                       // 0x00-0x0f
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                       // 0x10-0x1f
	100, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 10, 1, 10, 1,                   // 0x20-0x2f
	10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 1, 1, 1, 1, 1, 1,             // 0x30-0x3f
	1, 81, 15, 27, 42, 127, 22, 20, 61, 70, 1, 7, 40, 24, 67, 75,         // 0x40-0x4f
	19, 1, 59, 63, 90, 27, 9, 23, 1, 2, 1, 1, 0, 1, 0, 0,                 // 0x50-0x5f
	1, 81, 15, 27, 42, 127, 22, 20, 61, 70, 1, 7, 40, 24, 67, 75,         // 0x60-0x6f
	19, 1, 59, 63, 90, 27, 9, 23, 1, 2, 1, 1, 0, 0, 0, 0                  // 0x70-0x7f
};

static const int vASNIEnFreqPoints2[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, -1, -1, 0, -1, -1,          // 0x00-0x0f
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,       // 0x10-0x1f
	100, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 10, 1, 10, 1,                   // 0x20-0x2f
	10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 1, 1, 1, 1, 1, 1,             // 0x30-0x3f
	1, 81, 15, 27, 42, 127, 22, 20, 61, 70, 1, 7, 40, 24, 67, 75,         // 0x40-0x4f
	19, 1, 59, 63, 90, 27, 9, 23, 1, 2, 1, 1, 0, 1, 0, 0,                 // 0x50-0x5f
	1, 81, 15, 27, 42, 127, 22, 20, 61, 70, 1, 7, 40, 24, 67, 75,         // 0x60-0x6f
	19, 1, 59, 63, 90, 27, 9, 23, 1, 2, 1, 1, 0, 0, 0, -1                 // 0x70-0x7f
};

static int getANSIEnFreqPoints(size_t index)
{
	if (index >= _countof(vASNIEnFreqPoints)) {
		return -1;
	}
	return vASNIEnFreqPoints[index];
}

static char _idxToB64(size_t idx)
{
	if (idx >= _countof(b64Table)) {
		io_utils::logError("Bad arg to _idxToB64");
		return 0x7f;
	}
	return b64Table[idx];
}

static byte _b64ToIdx(char c)
{
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '+') {
		return 62;  // 26 + 26 + 10
	}
	if (c == '/') {
		return 63;
	}
	if (c == '=') {
		// Padding char
		return 0xff;
	}
	io_utils::logError("Bad arg to _b64ToIdx");
	return 0xff;
}

std::unique_ptr<byte[]> crypto_utils::hexToBin(const char* pHexBuf, size_t inCnt, size_t& outCnt)
{
	if (!pHexBuf || inCnt == 0) {
		return nullptr;
	}
	outCnt = 0;
	size_t nPairs = inCnt / 2;
	size_t extra = inCnt % 2;
	std::unique_ptr<byte[]>pOutBuf = std::unique_ptr<byte[]>(new byte[nPairs+1]);
	size_t ip = 0;
	for (size_t i = 0; i < nPairs; i++) {
		byte n1 = _hexByte(pHexBuf[ip++]);
		byte n2 = _hexByte(pHexBuf[ip++]);
		pOutBuf[outCnt++] = (n1 << 4) + n2;
	}
	if (extra == 1) {
		pOutBuf[outCnt++] = _hexByte(pHexBuf[ip++]);
	}
	return pOutBuf;
}

upCharArr crypto_utils::binToHex(const byte* pBuf, size_t inCnt, size_t& outCnt)
{
	if (!pBuf || inCnt == 0) {
		return nullptr;
	}
	outCnt = 0;
	auto pOutBuf = upCharArr(new char[inCnt*2 + 1]);
	for (size_t i = 0; i < inCnt; i++) {
		byte b = pBuf[i];
		byte b0 = b & 0xf;  		// lower nibble 
		byte b1 = (b >> 4) & 0xf;	// upper nibble 
		pOutBuf[outCnt++] = _byteToHexDigit(b1);
		pOutBuf[outCnt++] = _byteToHexDigit(b0);
	}
	pOutBuf[outCnt] = '\0';
	return pOutBuf;
}

upCharArr crypto_utils::binToTxtANSI(const byte* pBuf, size_t inCnt, size_t& outCnt)
{
	if (!pBuf || inCnt == 0) {
		return nullptr;
	}
	auto pOutBuf = upCharArr(new char[inCnt + 1]);
	for (size_t i = 0; i < inCnt; i++) {
		if (pBuf[i] > 0x7f) {
			pOutBuf[i] = '.';
		}
		else {
			pOutBuf[i] = static_cast<char>(pBuf[i]);
		}
	}
	pOutBuf[inCnt] = '\0';
	outCnt = inCnt;
	return pOutBuf;
}

upCharArr crypto_utils::binToBase64(const byte* pBuf, size_t inCnt, size_t& outCnt)
{
	if (!pBuf || inCnt == 0) {
		return nullptr;
	}
	size_t extraChars = inCnt % 3;
	size_t groups = inCnt / 3;
	size_t outBufSz = (groups + 1) * 4;
	outCnt = 0;
	size_t ip = 0;

	upCharArr pOutBuf = std::unique_ptr<char[]>(new char[outBufSz]);

	for (size_t i = 0; i < groups; i++) {
		char c0 = pBuf[ip++];
		char c1 = pBuf[ip++];
		char c2 = pBuf[ip++];
		pOutBuf[outCnt++] = _idxToB64(c0 >> 2);
		pOutBuf[outCnt++] = _idxToB64(((c0 & 0x3) << 4) | (c1 >> 4));
		pOutBuf[outCnt++] = _idxToB64(((c1 & 0xf) << 2) | (c2 >> 6));
		pOutBuf[outCnt++] = _idxToB64((c2 & 0x3f));
	}
	if (extraChars == 2) {
		char c0 = pBuf[ip++];
		char c1 = pBuf[ip++];
		pOutBuf[outCnt++] = _idxToB64(c0 >> 2);
		pOutBuf[outCnt++] = _idxToB64(((c0 & 0x3) << 4) | (c1 >> 4));
		pOutBuf[outCnt++] = _idxToB64((c1 & 0xf) << 2);
		pOutBuf[outCnt++] = '=';
	}
	else if (extraChars == 1) {
		char c0 = pBuf[ip++];
		pOutBuf[outCnt++] = _idxToB64(c0 >> 2);
		pOutBuf[outCnt++] = _idxToB64((c0 & 0x3) << 4);
		pOutBuf[outCnt++] = '=';
		pOutBuf[outCnt++] = '=';
	}
	pOutBuf[outCnt] = '\0';
	return pOutBuf;
}

std::unique_ptr<byte[]> crypto_utils::base64ToBin(const char* pB64Buf, size_t inCnt, size_t& outCnt, size_t blockSize, PaddingScheme padSch)
{
	// Assumption: CR-LF have already been stripped from input

	// Error out on non-multiples of 4 (TODO: could implement this)
	if (inCnt % 4) {
		io_utils::logError("Input to base64ToBin");
		return nullptr;
	}

	size_t groups = inCnt / 4;
	size_t dataSize = groups * 3;
	// If a block size was provided, round up the size of the buffer allocated to the nearest multiple of that size
	// Note this "padding" is different from the Base64 padding. This size may be pessimistic; we recompute
	// how many actual padding characters we need based on the actual data characters encountered.
	size_t paddedSize = (blockSize > 0 && dataSize % blockSize) ? (dataSize / blockSize + 1) * blockSize : dataSize;

	std::unique_ptr<byte[]>pRetBuf = std::unique_ptr<byte[]>(new byte[paddedSize]);
	auto pOutBuf = pRetBuf.get();
	int ib = 0;
	size_t oCnt = 0;
	for (size_t i = 0; i < groups - 1; i++) {
		byte i0 = _b64ToIdx(pB64Buf[ib++]);
		byte i1 = _b64ToIdx(pB64Buf[ib++]);
		byte i2 = _b64ToIdx(pB64Buf[ib++]);
		byte i3 = _b64ToIdx(pB64Buf[ib++]);

		pOutBuf[oCnt++] = i0 << 2 | ((i1 >> 4) & 0x3);
		pOutBuf[oCnt++] = i1 << 4 | ((i2 >> 2) & 0xf);
		pOutBuf[oCnt++] = i2 << 6 | i3;
	}
	// Handle last group separately - extra checking for Base64 padding chars
	byte i0 = _b64ToIdx(pB64Buf[ib++]);
	byte i1 = _b64ToIdx(pB64Buf[ib++]);
	byte i2 = _b64ToIdx(pB64Buf[ib++]);
	byte i3 = _b64ToIdx(pB64Buf[ib++]);

	pOutBuf[oCnt++] = i0 << 2 | ((i1 >> 4) & 0x3);
 	if (i2 == 0xff) {
 		//pOutBuf[oCnt++] = (i1 << 4) & 0x3;
 	}
 	else if (i3 == 0xff) {
 		pOutBuf[oCnt++] = i1 << 4 | ((i2 >> 2) & 0xf);
 		//pOutBuf[oCnt++] = i2 << 6;
 	}
 	else {
 		pOutBuf[oCnt++] = i1 << 4 | ((i2 >> 2) & 0xf);
 		pOutBuf[oCnt++] = i2 << 6 | i3;
 	}

	// Now fill in block padding if so requested
	size_t adjustedCnt = ((blockSize > 0) && oCnt % blockSize) ? (outCnt / blockSize + 1) * blockSize : oCnt;

	byte padByte = (padSch == PaddingScheme::PKCS_7) ? static_cast<byte>(adjustedCnt - oCnt) : 0;
	while (oCnt < adjustedCnt) {
		pOutBuf[oCnt++] = padByte;
	}
	outCnt = oCnt;
	return pRetBuf;
}

bool crypto_utils::convHexToBase64(const char* pHexFile, const char* pBase64File)
{
	size_t hexCnt = 0;
	std::unique_ptr<char[]>pHexBuf = io_utils::readTextFileStripCRLF(pHexFile, hexCnt);
	if (!pHexBuf) {
		return false;
	}

	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBinBuf = crypto_utils::hexToBin(pHexBuf.get(), hexCnt, binCnt);
	if (binCnt == 0 || !pBinBuf) {
		return false;
	}

	size_t b64Cnt = 0;
	std::unique_ptr<char[]> pB64Buf = crypto_utils::binToBase64(pBinBuf.get(), binCnt, b64Cnt);
	if (b64Cnt == 0 || !pB64Buf) {
		return false;
	}

	std::string ostr(pB64Buf.get());
	size_t nWritten = io_utils::writeTextFile(pBase64File, ostr.c_str(), ostr.length());

	return nWritten == ostr.length();
}

bool crypto_utils::convBase64ToHex(const char* pBase64File, const char* pHexFile)
{
	size_t base64Cnt = 0;
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileStripCRLF(pBase64File, base64Cnt);
	if (!pBase64Buf || base64Cnt == 0) {
		return false;
	}

	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBinBuf = crypto_utils::base64ToBin(pBase64Buf.get(), base64Cnt, binCnt);
	if (binCnt == 0 || !pBinBuf) {
		return false;
	}

	size_t hexCnt = 0;
	std::unique_ptr<char[]> pHexBuf = crypto_utils::binToHex(pBinBuf.get(), binCnt, hexCnt);
	if (hexCnt == 0 || !pHexBuf) {
		return false;
	}

	std::string ostr(pHexBuf.get());
	size_t nWritten = io_utils::writeTextFile(pHexFile, ostr.c_str(), ostr.length());

	return nWritten == ostr.length();
}

int crypto_utils::rateANSI(byte* pByteArray, size_t cnt)
{
	int score = 0;
	if (nullptr == pByteArray || cnt == 0) {
		return score;
	}

	for (int i = 0; i < cnt; i++) {
		int cRating = getANSIEnFreqPoints(pByteArray[i]);
// 		if (cRating < 0) {
// 			return 0;
// 		}
		score += cRating;
	}

	// Return total score normalized by buffer length
	return (score > 0) ? (score * 100) / (int)cnt : 0;
}

std::unique_ptr<char[]> crypto_utils::checkSingleByteXORAnsiH(const char* pHexBuf, const size_t inCnt, unsigned& o_key, int& o_score)
{
	// XOR the given text buffer against all possible single-byte keys
	// and return one with the highest ANSI frequency rating.
	// The rating score is returned in the output argument o_score.
	// The input array is hex encoded characters.

	o_score = 0;
	o_key = 0;
	if (!pHexBuf) {
		return nullptr;
	}
	size_t bin1Cnt = 0;
	std::unique_ptr<byte[]> pBinBuf = crypto_utils::hexToBin(pHexBuf, inCnt, bin1Cnt);

	return crypto_utils::checkSingleByteXORAnsi(pBinBuf.get(), bin1Cnt, o_key, o_score);
}

std::unique_ptr<char[]> crypto_utils::checkSingleByteXORAnsi(const byte* pInBuf, const size_t inCnt, unsigned& o_key, int& o_score)
{
	// XOR the given text buffer against all possible single-byte keys
	// and return one with the highest ANSI frequency rating.
	// The rating score is returned in the output argument o_score.
	// The input array is binary byte values.

	o_score = 0;
	o_key = 0;
	if (!pInBuf || inCnt==0) {
		return nullptr;
	}

	int highestScore = 0;
	byte bestX = 0;
	std::unique_ptr<byte[]> pTestBuf = std::unique_ptr<byte[]>(new byte[inCnt]);
	byte* pTb = pTestBuf.get();
	
	// Note that we're overwriting pTestBuf on each pass through the loop
	for (size_t key = 0; key <= 0xff; key++) {
		byte xval = key & 0xff;
		for (size_t i = 0; i < inCnt; i++) {
			pTb[i] = (pInBuf[i] ^ xval);
		}
		int score = crypto_utils::rateANSI(pTb, inCnt);
		if (score > highestScore) {
			bestX = xval;
			highestScore = score;
		}
	}

	// Re-compute best entry - faster than making copies at each step above
	for (size_t i = 0; i < inCnt; i++) {
		pTb[i] = (pInBuf[i] ^ bestX);
	}
	size_t outCnt = 0;
	std::unique_ptr<char[]> pBestStr = crypto_utils::binToTxtANSI(pTb, inCnt, outCnt);
	o_score = highestScore;
	o_key = bestX;
	return pBestStr;
}


std::unique_ptr<byte[]> crypto_utils::encryptRepeatingKey(const std::string& text, const std::string& key, size_t& outCnt)
{
	std::unique_ptr<byte[]> pBytes = std::unique_ptr<byte[]>(new byte[text.length()]);
	outCnt = text.length();
	const char* pTxt = text.c_str();
	const char* pKey = key.c_str();
	size_t keyLen = key.length();
	for (size_t idx = 0; idx < text.length(); idx++) {
		pBytes[idx] = pTxt[idx] ^ pKey[idx%keyLen];
	}
	return pBytes;
}


std::unique_ptr<char[]> crypto_utils::decryptRepeatingKey(const byte* pBuf, const size_t bufCnt, const byte* pKey, const size_t keyLen)
{
	if (!pBuf || bufCnt == 0 || keyLen == 0) {
		return nullptr;
	}

	std::unique_ptr<char[]> pTxt = std::unique_ptr<char[]>(new char[bufCnt+1]);
	char* pT = pTxt.get();

	for (size_t idx = 0; idx < bufCnt; idx++) {
		pT[idx] = pBuf[idx] ^ pKey[idx%keyLen];
	}
	pT[bufCnt] = '\0';
	return pTxt;
}

unsigned crypto_utils::countBits(byte x)
{
	unsigned count = 0;
	while (x > 0) {
		if ((x & 1) == 1) {
			count += 1;
		}
		x >>= 1;
	}
	return count;
}

unsigned crypto_utils::hammingDistance(byte x, byte y)
{
	return crypto_utils::countBits(x ^ y);
}

unsigned crypto_utils::hammingDistance(const byte* pX, size_t lenX, const byte* pY, size_t lenY)
{
	unsigned distance = 0;
	if (lenX != lenY) {
		io_utils::logError("Invalid inputs to hammingDistance: lengths must be equal");
		return distance;
	}
	for (size_t i = 0; i < lenX; i++) {
		distance += crypto_utils::hammingDistance(pX[i], pY[i]);
	}
	return distance;
}

unsigned crypto_utils::getKeyLengthRatings(const byte* pBytes, unsigned stKeyLen, unsigned endKeyLen, KeyLengthRatings& keyLengthRatings)
{
	// For each KEYSIZE in {range}
	//     compute the Hamming distance between first KEYSIZE bytes and second KEYSIZE bytes
	//     normalize (/KEYSIZE)
	//     the key length with the lowest Hamming distance is likely the correct one

	unsigned bestKeyLen = 0;
	float bestRating = 100000.0;

	for (unsigned keyLen = stKeyLen; keyLen <= endKeyLen; keyLen++) {

		const byte* pChunk1 = pBytes;
		const byte* pChunk2 = pChunk1 + keyLen;
		const byte* pChunk3 = pChunk2 + keyLen;
		const byte* pChunk4 = pChunk3 + keyLen;

		unsigned hd1 = crypto_utils::hammingDistance(pChunk1, keyLen, pChunk2, keyLen);
		unsigned hd2 = crypto_utils::hammingDistance(pChunk3, keyLen, pChunk4, keyLen);
		
		float normalizedDist = ((float)hd1 + (float)hd2)/ (2.0f * (float)keyLen);
		keyLengthRatings[keyLen] = normalizedDist;

		if (normalizedDist < bestRating) {
			bestKeyLen = keyLen;
			bestRating = normalizedDist;
		}
	}
	return bestKeyLen;
}

std::unique_ptr<char[]> crypto_utils::decodeUsingFixedKeyLength(const byte* pBinBuf, size_t binCnt, byte* pKey, size_t keyLength)
{
	std::vector<std::unique_ptr<char[]>> vBlockDecodings;

	// Break input into KEYLEN-sized blocks
	unsigned wholeBlocks = static_cast<unsigned>(binCnt / keyLength);
	unsigned extraBytes = static_cast<unsigned>(binCnt % keyLength);

	for (unsigned keyPos = 0; keyPos < keyLength; keyPos++) {

		unsigned bytesInBlock = keyPos < extraBytes ? wholeBlocks + 1 : wholeBlocks;
		std::unique_ptr<byte[]> pBytes = std::unique_ptr<byte[]>(new byte[bytesInBlock]);
		byte* pDest = pBytes.get();
		const byte* pSrc = &pBinBuf[keyPos];
		for (unsigned b = 0; b < bytesInBlock; b++) {
			*pDest++ = *pSrc;
			pSrc += keyLength;
		}
		unsigned keyByte = 0;
		int score = 0;
		std::unique_ptr<char[]> pDecodedStr = crypto_utils::checkSingleByteXORAnsi(pBytes.get(), bytesInBlock, keyByte, score);
		vBlockDecodings.push_back(std::move(pDecodedStr));
		pKey[keyPos] = keyByte;
	}

	// Assemble the output message from the decoded individual blocks
	std::unique_ptr<char[]> pCleartext = std::unique_ptr<char[]>(new char[binCnt + 1]);
	char* pCleartextBuf = pCleartext.get();
	for (size_t b = 0; b < binCnt; b++) {
		*pCleartextBuf++ = vBlockDecodings[b%keyLength][b / keyLength];  // TODO - recode for efficiency
	}

	// Alternatively (checked: we get the same answer):
	// Decode the whole message with the full computed key and see if it's the same as what we got above
	//std::unique_ptr<char[]> pCleartext = crypto_utils::decryptRepeatingKey(pBinBuf, binCnt, pKey, keyLength);

	return pCleartext;
}

bool crypto_utils::checkDuplicateBlocks(const std::string& str, size_t blockSize)
{
	std::unordered_set<std::string> uset;
	for (size_t pos = 0; pos < str.length(); pos += blockSize) {
		std::string s = str.substr(pos, blockSize);
		auto itr = uset.find(s);
		if (itr != uset.end()) {
			// we found a duplicate sub-string
			std::cout << "String has a duplicated block at position " << pos << std::endl;
			return true;
		}
		uset.emplace(s);
	}
	return false;
}

int crypto_utils::getLongestRepeatedPattern(const byte* pBytes, size_t nBytes)
{
	const byte* pCurrent = pBytes;
	const byte* pEnd = pCurrent + nBytes;
	int highCnt = 0;
	int currCnt = 0;
	const byte* pComp1 = nullptr;
	const byte* pComp2 = nullptr;

	while (pCurrent < pEnd) {
		currCnt = 0;
		pComp1 = pCurrent;
		pComp2 = pComp1;
		++pComp2;
	
		while (pComp2 < pEnd && *pComp2++ != *pComp1);
		if (pComp2 < pEnd) {
			++currCnt;
			++pComp1;
		}
		while (pComp2 < pEnd && *pComp2++ == *pComp1++) {
			++currCnt;
		}

		if (currCnt > highCnt) {
			highCnt = currCnt;
		}
		++pCurrent;
	}

	return highCnt;
}


// XOR a block 
// pDest could be the same as one of the inputs
void crypto_utils::xorBlock(byte* pDest, const byte* pIn1, const byte* pIn2, size_t cnt)
{
	for (size_t i = 0; i < cnt; ++i) {
		pDest[i] = pIn1[i] ^ pIn2[i];
	}
}

unsigned int crypto_utils::getRandomNumber()
{
	unsigned int val = 0;
	errno_t rc = rand_s(&val);
	return val;
}

byte crypto_utils::getRandomByte()
{
	unsigned int val = 0;
	errno_t rc = rand_s(&val);
	return static_cast<byte>(val & 0xff);
}

bool crypto_utils::getRandomBool()
{
	unsigned int val = 0;
	errno_t rc = rand_s(&val);
	return (val & 0x1) ? true : false;
}

void crypto_utils::generateKey(byte* pKey, size_t len)
{
	for (size_t i = 0; i < len; ++i) {
		*pKey++ = getRandomByte();
	}
}

byte_string crypto_utils::getRandomBytes(const size_t nMaxLen)
{
	byte_string retStr;

	size_t nBytes = getRandomNumber() % nMaxLen;
	retStr.reserve(nBytes+1);
	for (size_t i = 0; i < nBytes; ++i) {
		retStr += getRandomByte();
	}

	return retStr;
}


size_t crypto_utils::paddedSize(size_t inpSz, size_t blkSz)
{
	if (blkSz == 0) {
		return inpSz;
	}
	return (inpSz / blkSz + 1) * blkSz;
}

bool crypto_utils::stripPKCS7Padding(const std::string& str, std::string& outStr, size_t blockSize)
{
	size_t inputLen = str.length();
	if (inputLen % blockSize) {
		// Input is not a multiple of the block size - can't be padded correctly
		return false;
	}
	size_t startIdxLastBlock = ((inputLen / blockSize) - 1) * blockSize;
	std::string sLastBlock = str.substr(startIdxLastBlock, blockSize);
	char *pEnd = const_cast<char *>(sLastBlock.c_str()) + (blockSize - 1);
	char padChar = *pEnd;
	if (padChar == 0 || padChar > blockSize) {
		return false;
	}
	for (size_t i = 0; i < padChar; ++i) {
		if (*pEnd != padChar) {
			return false;
		}
		--pEnd;
	}

	std::string sTrimmedLastBlock = sLastBlock.substr(0, blockSize - padChar);
	outStr = str.substr(0, startIdxLastBlock);  // This is also the length of all blocks not including the last one
	outStr += sTrimmedLastBlock;
	return true;
}
