/*
*  Implementation of challenges, set 2
*/



#include "challenges.h"
#include "utils.h"
#include "aes.h"
#include "backend.h"

using namespace io_utils;


bool Challenges::Set2Ch10()
{
	// AES in CBC mode
	static const char* pInFile = "./data/set2/challenge10/10.txt";   // Base64
	static const char* pOutputFile = "./data/set2/challenge10/decrypted.txt";
	static const char* outputFileHex = "./data/set2/challenge10/decryptedHex.txt";
	static const char* inputFileHex = "./data/set2/challenge10/encryptedHex.txt";


#if 0
	// Write out a hex version of the encrypted input (e.g. to paste to a web-site decryption tool)
	size_t inpHexCnt = 0;
	std::unique_ptr<char[]> pInputHex = crypto_utils::binToHex((byte*)(pBinBytes.get()), binCnt, inpHexCnt);
	std::string hstr(pInputHex.get());
	size_t nhWritten = io_utils::writeTextFile(inputFileHex, hstr.c_str(), hstr.length());
	std::cout << "Wrote " << nhWritten << " hex characters to " << inputFileHex << std::endl;
#endif

	static const byte bKey[] = "YELLOW SUBMARINE";
	std::string key("YELLOW SUBMARINE");

	Aes aes(128, Aes::CBC);
	aes.SetKey(bKey, key.length());
	aes.Read(pInFile, FileType::BASE64);
	aes.Decrypt();
	size_t nWritten = aes.Write(pOutputFile, FileType::BINARY);

	bool bRc = (nWritten != 0);
	std::cout << "Wrote " << nWritten << " bytes to " << pOutputFile << std::endl;

#if 0
	// Write out the decrypted file in hex
	size_t hexCnt = 0;
	std::unique_ptr<char[]> pResultsHex = crypto_utils::binToHex((byte*)(pDecrypted.get()), binCnt, hexCnt);
	std::string ostr(pResultsHex.get());
	nWritten = io_utils::writeTextFile(outputFileHex, ostr.c_str(), ostr.length());
	std::cout << "Wrote " << nWritten << " hex characters to " << outputFileHex << std::endl;
#endif
	return bRc;
}

bool Challenges::Set2Ch11()
{
	// This is the plain text to submit to the encryption oracle
	static const char pTxt[] = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnop";
	static const size_t nTrials = 100;
	int detectedModeCnt[3]{ 0 };

	Aes aes(128);

	for (size_t i = 0; i < nTrials; ++i) {

		const std::string strResult = Backend::EncryptionOracle_2_11(pTxt, _countof(pTxt) - 1);
		const byte* pResult = reinterpret_cast<const byte*>(strResult.c_str()); 
		int detectedMode = aes.DetectMode(pResult, strResult.length());
		detectedModeCnt[detectedMode]++;
	}

	std::cout << "Counters: " << std::endl;
	std::cout << "ECB " << detectedModeCnt[Aes::ECB] << std::endl;
	std::cout << "CBC " << detectedModeCnt[Aes::CBC] << std::endl;
	std::cout << "UNKNOWN " << detectedModeCnt[Aes::AES_UNKNOWN] << std::endl;

	return true;
}

// Helper functions for Set2Ch12
static void _setInput212(byte* pTxt, size_t sz)
{
	for (size_t j = 0; j < sz; ++j) {
		pTxt[j] = 'A';
	}
	pTxt[sz] = '\0';

}

static void _setInput212a(byte* pTxt, size_t nPrepend, byte* pResultsBuf, size_t nResults)
{
	for (size_t j = 0; j < nPrepend; ++j) {
		*pTxt++ = 'A';
	}
	for (size_t j = 0; j < nResults; ++j) {
		*pTxt++ = *pResultsBuf++;
	}
	*pTxt = '\0';
}


bool Challenges::Set2Ch12()
{

	// Discover block size of cipher being used by the Oracle
	static const size_t kMaxBlockSz = 32;
	byte txtBuf[kMaxBlockSz + 1]{ 0 };
	size_t resultIdx = 0;
	size_t resultSz = 0;
	size_t nDetectedBlkSz = 0;
	int eDetectedMode = Aes::AES_UNKNOWN;
	std::unique_ptr<byte[]> pCurrResult = nullptr;
	std::unique_ptr<byte[]> pLastResult = nullptr;

	Aes aes(128);  // used for DetectMode calls

	for (size_t i = 1; i < kMaxBlockSz; ++i) {

		_setInput212(txtBuf, i);

		pCurrResult = Backend::EncryptionOracle_2_12(txtBuf, i);
		if (byteCompare(pCurrResult.get(), pLastResult.get(), i - 1)) {
			nDetectedBlkSz = i - 1;
			break;
		}
		pLastResult = std::move(pCurrResult);

	}

	std::cout << std::endl << "Block size " << nDetectedBlkSz << " detected" << std::endl;

	// Detect which AES mode 
	// TODO (same as previous challenge)
	static const char* pOutTxt = (eDetectedMode == Aes::ECB) ? "ECB " : "UNKNOWN";
	std::cout << "Detected Mode: " << pOutTxt << std::endl;

	// TODO: Change oracle to return byte count
	// For now just hard-code the number of blocks to figure out:
	size_t nBlocksReturned = 3;
	size_t nCharsToDecrypt = nBlocksReturned * nDetectedBlkSz;
	size_t nStartIdxWorkingBlk = (nBlocksReturned - 1)*nDetectedBlkSz;
	std::unique_ptr<byte[]> spResultBuf(new byte[nCharsToDecrypt + 1]);
	byte* pResultBuf = spResultBuf.get();
	SecureZeroMemory(pResultBuf, nCharsToDecrypt+1);
	std::unique_ptr<byte[]> spPrependBuf(new byte[nCharsToDecrypt + 1]);
	byte* pPrependBuf = spPrependBuf.get();
	SecureZeroMemory(pPrependBuf, nCharsToDecrypt+1);


	// Get "nBlocksReturned" blocks of the Oracle's internal text
	for (size_t offset = 1; offset <= nCharsToDecrypt; ++offset) {
		// Number of 'A' chars to prepend == nCharsToDecrypt - offset (one less each time through the loop)
		size_t nLeadingChars = nCharsToDecrypt - offset;

		// Number of results characters (plain-text we've already figured out) == resultIdx
		_setInput212a(pPrependBuf, nLeadingChars, pResultBuf, resultIdx);

		// Create the dictionary for the current leading {block-1} chars plus all possible 
		// values for the last byte position in the block
		std::unordered_map<byte_string, byte> dictionary;
		for (int bv = 0; bv <= 0xff; ++bv) {
			byte bVal = static_cast<byte>(bv);
			pPrependBuf[nCharsToDecrypt - 1] = bVal;
			pPrependBuf[nCharsToDecrypt] = '\0';
			std::unique_ptr<byte[]> pResult = Backend::EncryptionOracle_2_12(pPrependBuf, nCharsToDecrypt);
			byte_string sResult(pResult.get(), nCharsToDecrypt);
			// We can restrict the dictionary entry to the block of output currently being worked on.
			byte_string sTrunc(sResult, nStartIdxWorkingBlk, nDetectedBlkSz);
			std::pair<byte_string, byte>entry(sTrunc, bVal);
			dictionary.insert(entry);
		}

		// Now get the output for the short input (just the remaining leading chars)
		pPrependBuf[nLeadingChars] = '\0';
		std::unique_ptr<byte[]> pResult = Backend::EncryptionOracle_2_12(pPrependBuf, nLeadingChars);
		// Find the resulting cipher text in our dictionary
		byte_string sResult(pResult.get(), nCharsToDecrypt);
		byte_string sTrunc(sResult, nStartIdxWorkingBlk, nDetectedBlkSz);
		std::unordered_map<byte_string, byte>::const_iterator fnd = dictionary.find(sTrunc);
		if (fnd != dictionary.end()) {
			pResultBuf[resultIdx++] = fnd->second;
		}
		else {
			//std::cout << "Problem - returned cipher text not found in dictionary!" << std::endl;
			pResultBuf[resultIdx++] = '?';
		}

	}

	std::cout << "First " << nBlocksReturned << " blocks of text: " << std::endl << pResultBuf << std::endl;

	return true;

}

static void _setInput213(std::string& tstAddr, size_t sz)
{
	tstAddr = "a@";

	for (size_t j = 2; j < sz; ++j) {
		tstAddr += 'B';
	}
}

static void _setInput213a(std::string& prependStr, size_t nLeadingChars, const std::string& resultStr)
{
	_setInput213(prependStr, nLeadingChars);
	prependStr += resultStr;
}

bool Challenges::Set2Ch13()
{

	static const size_t kMaxBlockSz = 32;
	size_t nDetectedBlkBoundary = 0;
	byte_string lastResult;
	byte_string currResult;

	for (size_t i = 3; i < kMaxBlockSz; ++i) {

		std::string testStr;
		_setInput213(testStr, i);
		currResult = Backend::EncryptionOracle_2_13(testStr);

		if (byteCompare(currResult.c_str(), lastResult.c_str(), i - 1)) {
			nDetectedBlkBoundary = i - 1;  // -1: lastResult was the end of a block
			break;
		}
		lastResult = currResult;
	}

	std::cout << std::endl << "Block boundary detected for email address of length: " << nDetectedBlkBoundary << std::endl;


	// Now determine full block size by seeing how many encrypted characters the last two results have in common
	size_t nCurrBytes = currResult.length();
	size_t nLastBytes = lastResult.length();
	size_t nBlockSize = nBytesCompare(currResult.c_str(), lastResult.c_str(), nLastBytes < nCurrBytes ? nLastBytes : nCurrBytes);

	std::cout << "Block size detected: " << nBlockSize << std::endl;
	std::cout << "Number of bytes returned for " << nDetectedBlkBoundary << "-character email address: " << nLastBytes << std::endl;

	// The approach of Set2Ch12 won't work to read the input because characters we want to get the
	// encryption for (e.g. '&', '=') will not be allowed by the oracle encoding.

	// Figure out how much padding is in the last block
	size_t paddingBytes = 0;
	for (size_t i = nDetectedBlkBoundary+1; i < nDetectedBlkBoundary + nBlockSize + 1; ++i) {
		std::string testStr;
		_setInput213(testStr, i);
		currResult = Backend::EncryptionOracle_2_13(testStr);
		size_t testLen = currResult.length();
		if (currResult.length() > nLastBytes) {
			break;
		}
		++paddingBytes;
	}

	std::cout << "Padding bytes in last block: " << paddingBytes << std::endl;

	// Take blocks 1 and 2 from the result for this input
	std::string testStr1 = "bob@evil.com";
	byte_string  strResult1 = Backend::EncryptionOracle_2_13(testStr1);

	// Take block 3 from the result for this input
	std::string testStr2 = "a@abcdefghijklmnopqrstuvwxadmin";
	byte_string  strResult2 = Backend::EncryptionOracle_2_13(testStr2);
	
	size_t b2 = 2 * nBlockSize;
	byte_string forgedDesc(strResult1, 0, b2);
	forgedDesc += strResult2.substr(b2, nBlockSize);
	Backend::Add_User_2_13(forgedDesc);

	return true;

}

bool Challenges::Set2Ch14()
{
	// Oracle:
	// Change this (and 2_12) to supply return byte count
	// std::unique_ptr< byte[] >  Backend::EncryptionOracle_2_14(const byte* pInput, size_t len)

	return true;
}

