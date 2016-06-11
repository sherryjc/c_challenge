
#include <stdio.h>
#include "utils.h"

static void logError(const char* str)
{
	fprintf(stderr, "Error: %s\n", str);
}

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
		return b - 0xa + 'A';
	}
	return b + '0';
}

std::unique_ptr<byte[]> io_utils::readBinFile(const char* pFileName, size_t& outSz)
{
	outSz = 0;
	FILE* pFile = fopen(pFileName, "rb");
	if (nullptr == pFile) { 
		logError(_T("fopen")); 
		return nullptr; 
	}

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	long lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	std::unique_ptr<byte[]>pBuffer = std::unique_ptr<byte[]>(new byte[lSize]);
	if (nullptr == pBuffer) { 
		logError(_T("new")); 
		fclose(pFile);
		return nullptr; 
	}

	// copy the file into the buffer:
	size_t itemsRead = fread(pBuffer.get(), 1, lSize, pFile);
	if (itemsRead != lSize) { 
		logError(_T("fread")); 
	}
	outSz = itemsRead;
	fclose(pFile);
	return pBuffer;
}

#if 0
std::unique_ptr<wchar_t[]> io_utils::readTextFileW(const wchar_t* pFileName, int encoding)
{
	FILE * pFile = nullptr;
	// TODO: handle encoding
	errno_t err = _wfopen_s(&pFile, pFileName, _T("r"));
	if (nullptr == pFile || err != 0) {
		logError(_T("_wfopen_s"));
		return nullptr;
	}

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	long lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	std::unique_ptr<wchar_t[]>pBuffer = std::unique_ptr<wchar_t[]>(new wchar_t[lSize]);
	if (nullptr == pBuffer) {
		logError(_T("new"));
		fclose(pFile);
		return nullptr;
	}

	// copy the file into the buffer:
	size_t itemsRead = fread(pBuffer.get(), 1, lSize, pFile);
	if (itemsRead != lSize) {
		logError(_T("fread"));
	}

	fclose(pFile);
	return pBuffer;
}
#endif

std::unique_ptr<char[]> io_utils::readTextFileA(const char* pFileName)
{
	FILE * pFile = fopen(pFileName, "r");
	if (nullptr == pFile) {
		logError(_T("fopen"));
		return nullptr;
	}

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	long lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	std::unique_ptr<char[]>pBuffer = std::unique_ptr<char[]>(new char[lSize+1]);
	if (nullptr == pBuffer) {
		logError(_T("new"));
		fclose(pFile);
		return nullptr;
	}

	// copy the file into the buffer:
	size_t itemsRead = fread(pBuffer.get(), sizeof(char), lSize, pFile);
	if (itemsRead != lSize) {
		logError(_T("fread"));
	}
	pBuffer[itemsRead] = '\0';
	fclose(pFile);
	return pBuffer;
}

size_t io_utils::writeBinFile(const char* pFileName, const char* pBuffer, size_t cch)
{
	return writeTextFileA(pFileName, pBuffer, cch, true);
}

size_t io_utils::writeTextFileA(const char* pFileName, const char* pBuffer, size_t cch, bool bRaw)
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





/*****************************************/
/*    Crypto Utils                       */
/*****************************************/


static const char b64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char _idxToB64(size_t idx)
{
	if (idx >= _countof(b64Table)) {
		logError("Bad arg to _idxToB64");
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
	logError("Bad arg to _b64ToIdx");
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

std::unique_ptr<char[]> crypto_utils::binToHex(const byte* pBuf, size_t inCnt, size_t& outCnt)
{
	if (!pBuf || inCnt == 0) {
		return nullptr;
	}
	outCnt = 0;
	std::unique_ptr<char[]>pOutBuf = std::unique_ptr<char[]>(new char[inCnt*2 + 1]);
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

std::unique_ptr<char[]> crypto_utils::binToBase64(const byte* pBuf, size_t inCnt, size_t& outCnt)
{
	if (!pBuf || inCnt == 0) {
		return nullptr;
	}
	size_t extraChars = inCnt % 3;
	size_t groups = inCnt / 3;
	size_t outBufSz = (groups + 1) * 4;
	outCnt = 0;
	size_t ip = 0;

	std::unique_ptr<char[]>pOutBuf = std::unique_ptr<char[]>(new char[outBufSz]);

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

std::unique_ptr<byte[]> crypto_utils::base64ToBin(const char* pB64Buf, size_t inCnt, size_t& outCnt)
{
	// Make sure CR-LF have been stripped from input
	// See if we need to allow for non-multiples of 4
	if (inCnt % 4) {
		logError("Input to base64ToBin");
		return nullptr;
	}

	size_t groups = inCnt / 4;
	std::unique_ptr<byte[]>pOutBuf = std::unique_ptr<byte[]>(new byte[groups*3]);
	int ib = 0;
	outCnt = 0;
	for (size_t i = 0; i < groups - 1; i++) {
		byte i0 = _b64ToIdx(pB64Buf[ib++]);
		byte i1 = _b64ToIdx(pB64Buf[ib++]);
		byte i2 = _b64ToIdx(pB64Buf[ib++]);
		byte i3 = _b64ToIdx(pB64Buf[ib++]);

		pOutBuf[outCnt++] = i0 << 2 | ((i1 >> 4) & 0x3);
		pOutBuf[outCnt++] = i1 << 4 | ((i2 >> 2) & 0xf);
		pOutBuf[outCnt++] = i2 << 6 | i3;
	}
	// Handle last group separately - extra checking for padding chars
	byte i0 = _b64ToIdx(pB64Buf[ib++]);
	byte i1 = _b64ToIdx(pB64Buf[ib++]);
	byte i2 = _b64ToIdx(pB64Buf[ib++]);
	byte i3 = _b64ToIdx(pB64Buf[ib++]);

	pOutBuf[outCnt++] = i0 << 2 | ((i1 >> 4) & 0x3);
	if (i2 == 0xff) {
		pOutBuf[outCnt++] = (i1 << 4) & 0x3;
	}
	else if (i3 == 0xff) {
		pOutBuf[outCnt++] = i1 << 4 | ((i2 >> 2) & 0xf);
		pOutBuf[outCnt++] = i2 << 6;
	}
	else {
		pOutBuf[outCnt++] = i1 << 4 | ((i2 >> 2) & 0xf);
		pOutBuf[outCnt++] = i2 << 6 | i3;
	}

	return pOutBuf;
}

bool crypto_utils::convHexToBase64(const char* pHexFile, const char* pBase64File)
{
	std::unique_ptr<char[]>pHexBuf = io_utils::readTextFileA(pHexFile);
	if (!pHexBuf) {
		return false;
	}

	std::string s(pHexBuf.get());
	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBinBuf = crypto_utils::hexToBin(pHexBuf.get(), s.length(), binCnt);
	if (binCnt == 0 || !pBinBuf) {
		return false;
	}

	size_t b64Cnt = 0;
	std::unique_ptr<char[]> pB64Buf = crypto_utils::binToBase64(pBinBuf.get(), binCnt, b64Cnt);
	if (b64Cnt == 0 || !pB64Buf) {
		return false;
	}

	std::string ostr(pB64Buf.get());
	size_t nWritten = io_utils::writeTextFileA(pBase64File, ostr.c_str(), ostr.length());

	return nWritten == ostr.length();
}

bool crypto_utils::convBase64ToHex(const char* pBase64File, const char* pHexFile)
{
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileA(pBase64File);
	if (!pBase64Buf) {
		return false;
	}

	std::string s(pBase64Buf.get());
	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBinBuf = crypto_utils::base64ToBin(pBase64Buf.get(), s.length(), binCnt);
	if (binCnt == 0 || !pBinBuf) {
		return false;
	}

	size_t hexCnt = 0;
	std::unique_ptr<char[]> pHexBuf = crypto_utils::binToHex(pBinBuf.get(), binCnt, hexCnt);
	if (hexCnt == 0 || !pHexBuf) {
		return false;
	}

	std::string ostr(pHexBuf.get());
	size_t nWritten = io_utils::writeTextFileA(pHexFile, ostr.c_str(), ostr.length());

	return nWritten == ostr.length();
}
