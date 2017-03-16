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
	byte resultBuf[kMaxBlockSz + 1]{ 0 };
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

	// Detect the AES mode 
	// TODO
	static const char* pOutTxt = (eDetectedMode == Aes::ECB) ? "ECB " : "UNKNOWN";
	std::cout << "Detected Mode: " << pOutTxt << std::endl;

	// Get one block's worth of the Oracle's internal text
	for (size_t offset = 1; offset <= nDetectedBlkSz; ++offset) {
		// Number of 'A' chars to prepend == nDetectedBlkSz - offset (one less each time through the loop)
		size_t nLeadingChars = nDetectedBlkSz - offset;
		// Number of results characters (plaintext we've already figured out) == resultIdx
		_setInput212a(txtBuf, nLeadingChars, resultBuf, resultIdx);

		// Create the dictionary for the current leading {block-1} chars plus all possible 
		// values for the last byte position in the block
		std::unordered_map<std::string, byte> dictionary;
		for (int bv = 0; bv <= 0xff; ++bv) {
			byte bVal = static_cast<byte>(bv);
			txtBuf[nDetectedBlkSz - 1] = bVal;
			txtBuf[nDetectedBlkSz] = '\0';
			std::unique_ptr<byte[]> pResult = Backend::EncryptionOracle_2_12(txtBuf, nDetectedBlkSz);
			// Truncate the output to the block size
			std::string sResult = reinterpret_cast<char*>(pResult.get());
			std::string sTrunc(sResult, 0, nDetectedBlkSz);
			std::pair<std::string, byte>entry(sTrunc, bVal);
			dictionary.insert(entry);
		}

		// Now get the output for the short input (just the remaining leading chars)
		txtBuf[nLeadingChars] = '\0';
		std::unique_ptr<byte[]> pResult = Backend::EncryptionOracle_2_12(txtBuf, nLeadingChars);
		// Find the resulting cipher text in our dictionary
		std::string sResult = reinterpret_cast<char*>(pResult.get());
		std::string sTrunc(sResult, 0, nDetectedBlkSz);
		std::unordered_map<std::string, byte>::const_iterator fnd = dictionary.find(sTrunc);
		if (fnd != dictionary.end()) {
			resultBuf[resultIdx++] = fnd->second;
		}
		else {
			std::cout << "Problem - returned cipher text not found in dictionary!" << std::endl;
			return false;
		}

	}

	std::cout << "First block of text: " << std::endl << resultBuf << std::endl;

	return true;

}



bool Challenges::Set2Ch13()
{

	std::string emailAddr = "Jack@beanstalk.com";
	std::string encryptedText = Backend::Oracle_2_13(emailAddr);
	Backend::Add_User_2_13(encryptedText);

	return true;
}