
#include <stdio.h>
#include "utils.h"




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

std::unique_ptr<byte[]> io_utils::readBinFile(const char* pFileName, size_t& outSz)
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

	// allocate memory to contain the whole file:
	std::unique_ptr<byte[]>pBuffer = std::unique_ptr<byte[]>(new byte[lSize]);
	if (nullptr == pBuffer) { 
		logError("new"); 
		fclose(pFile);
		return nullptr; 
	}

	// copy the file into the buffer:
	size_t itemsRead = fread(pBuffer.get(), 1, lSize, pFile);
	if (itemsRead != lSize) { 
		logError("fread"); 
	}
	outSz = itemsRead;
	fclose(pFile);
	return pBuffer;
}

std::unique_ptr<char[]> io_utils::readTextFile(const char* pFileName, size_t& outCnt)
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
	std::unique_ptr<char[]>pBuffer = std::unique_ptr<char[]>(new char[lSize+1]);
	if (nullptr == pBuffer) {
		logError("new");
		fclose(pFile);
		return nullptr;
	}

	// copy the file into the buffer:
	size_t itemsRead = fread(pBuffer.get(), sizeof(char), lSize, pFile);
	if (itemsRead == 0) {   // itemsRead might not == lSize due to \n\r issues
		logError("fread");
	}
	pBuffer[itemsRead] = '\0';
	outCnt = itemsRead;
	fclose(pFile);
	return pBuffer;
}

std::unique_ptr<char[]> io_utils::readTextFileStripCRLF(const char* pFileName, size_t& outCnt)
{
	size_t readCnt = 0;
	std::unique_ptr<char[]> pTxt = io_utils::readTextFile(pFileName, readCnt);
	std::unique_ptr<char[]> pStrippedTxt = stripCRLF(pTxt.get(), readCnt, outCnt);
	return pStrippedTxt;
}

size_t io_utils::writeBinFile(const char* pFileName, const char* pBuffer, size_t cch)
{
	return writeTextFile(pFileName, pBuffer, cch, true);
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


std::unique_ptr<char[]> io_utils::stripCRLF(const char* pCharBuf, size_t inCnt, size_t& strippedCnt)
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
	return pStrippedBuffer;
}

void dbg_utils::displayBytes(const byte* pBytes, size_t cnt)
{
	for (size_t i=0; i<cnt; i++) {
		std::cout << pBytes[i];
	}
	std::cout << std::endl;
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

std::unique_ptr<char[]> crypto_utils::binToTxtANSI(const byte* pBuf, size_t inCnt, size_t& outCnt)
{
	if (!pBuf || inCnt == 0) {
		return nullptr;
	}
	std::unique_ptr<char[]>pOutBuf = std::unique_ptr<char[]>(new char[inCnt + 1]);
	for (size_t i = 0; i < inCnt; i++) {
		if (pBuf[i] > 0x7f) {
			pOutBuf[i] = '.';
		}
		else {
			pOutBuf[i] = static_cast<char>(pBuf[i]);
		}
	}
	pOutBuf[inCnt] = '\0';
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
	// Assumption: CR-LF have already been stripped from input

	// Error out on non-multiples of 4 (TODO: could implement this)
	if (inCnt % 4) {
		io_utils::logError("Input to base64ToBin");
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
		if (cRating < 0) {
			return 0;
		}
		score += cRating;
	}

	// Return total score normalized by buffer length
	return static_cast<int>((score*100)/cnt);
}

std::unique_ptr<char[]> crypto_utils::checkSingleByteXORAnsi(const char* pHexBuf, const size_t inCnt, unsigned& o_key, int& o_score)
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
		int score = crypto_utils::rateANSI(pTestBuf.get(), inCnt);
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
	unsigned bestRating = 0xffffffff;

	for (unsigned key = stKeyLen; key <= endKeyLen; key++) {

		const byte* pChunk1 = pBytes;
		const byte* pChunk2 = pBytes + key;

		unsigned normalizedDist = crypto_utils::hammingDistance(pChunk1, key, pChunk2, key) / key;
		keyLengthRatings[key] = normalizedDist;

		if (normalizedDist < bestRating) {
			bestKeyLen = key;
			bestRating = normalizedDist;
		}
	}
	return bestKeyLen;
}
