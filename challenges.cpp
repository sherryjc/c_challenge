
/*
 *
 */


#include "challenges.h"
#include "utils.h"

bool Challenges::Set1Ch1()
{
	// Convert hex to base64 and back
	static const char* pHexFile = "./data/set1/challenge1/input.hex";
	static const char* pOutBase64 = "./data/set1/challenge1/outputB64.hex";
	static const char* pHexFileOut = "./data/set1/challenge1/roundtrip.hex";
	static const char* pHexFile2 = "./data/set1/challenge1/input2.hex";
	static const char* pOutBase64_2 = "./data/set1/challenge1/outputB64_2.hex";
	static const char* pHexFileOut2 = "./data/set1/challenge1/roundtrip2.hex";

	// Original input file from the Cryptopals web site
	bool bRc = crypto_utils::convHexToBase64(pHexFile, pOutBase64);
	bRc &= crypto_utils::convBase64ToHex(pOutBase64, pHexFileOut);
	
	// This input file has CR-LFs
	bRc &= crypto_utils::convHexToBase64(pHexFile2, pOutBase64_2);
	bRc &= crypto_utils::convBase64ToHex(pOutBase64_2, pHexFileOut2);
	return bRc;
}

bool Challenges::Set1Ch2()
{
	// test fixed XOR computation
	static const char* input1 = "./data/set1/challenge2/input1.hex";
	static const char* input2 = "./data/set1/challenge2/input2.hex";
	static const char* outputFile = "./data/set1/challenge2/output.hex";

	size_t buf1Cnt = 0, buf2Cnt = 0;
	std::unique_ptr<char[]>pTxtBuf1 = io_utils::readTextFileStripCRLF(input1, buf1Cnt);
	std::unique_ptr<char[]>pTxtBuf2 = io_utils::readTextFileStripCRLF(input2, buf2Cnt);

	if (!pTxtBuf1 || buf1Cnt == 0 | !pTxtBuf2 | buf2Cnt == 0) {
		return false;
	}
	if (buf1Cnt != buf2Cnt) {
		io_utils::logError("input lengths differ");
		return false;
	}

	size_t bin1Cnt = 0, bin2Cnt = 0;
	std::unique_ptr<byte[]> pBinBuf1 = crypto_utils::hexToBin(pTxtBuf1.get(), buf1Cnt, bin1Cnt);
	std::unique_ptr<byte[]> pBinBuf2 = crypto_utils::hexToBin(pTxtBuf2.get(), buf2Cnt, bin2Cnt);

	if (bin1Cnt == 0 || !pBinBuf1 || bin2Cnt == 0 || !pBinBuf2 || bin1Cnt != bin2Cnt) {
		return false;
	}

	std::unique_ptr<byte[]>pResultsBuf = std::unique_ptr<byte[]>(new byte[bin1Cnt]);

	// XOR the two buffers
	for (size_t i = 0; i < bin1Cnt; i++) {
		pResultsBuf[i] = pBinBuf1[i] ^ pBinBuf2[i];
	}

	size_t hexCnt = 0;
	std::unique_ptr<char[]> pResultsHex = crypto_utils::binToHex(pResultsBuf.get(), bin1Cnt, hexCnt);
	std::string ostr(pResultsHex.get());
	size_t nWritten = io_utils::writeTextFile(outputFile, ostr.c_str(), ostr.length());

	return nWritten == ostr.length();
}

bool Challenges::Set1Ch3()
{
	// Break single-byte XOR encryption

	static const char* input = "./data/set1/challenge3/input.hex";
	size_t txtBufCnt = 0;
	std::unique_ptr<char[]>pTxtBuf = io_utils::readTextFileStripCRLF(input, txtBufCnt);
	if (!pTxtBuf) {
		return false;
	}
	int score = 0;
	unsigned key = 0;
	std::unique_ptr<char[]> pDecodedStr = crypto_utils::checkSingleByteXORAnsi(pTxtBuf.get(), txtBufCnt, key, score);

	std::cout << "Decoded string: " << pDecodedStr.get() << std::endl << "key: " << key << " score: " << score << std::endl;

	return true;
}

class ScoredString
{
public:
	ScoredString(const char* pChars, int score) : m_str(pChars), m_score(score) {}
	const std::string& StrRef() const { return m_str; }
	int Score() const { return m_score; }
private:
	std::string	m_str;
	int			m_score;
};

using ScoredStrings = std::vector<ScoredString>;


bool Challenges::Set1Ch4()
{
	// Detect single-byte XOR encryption

	// TODO - strip trailing CR-LF; this is really a hex file 
	static const char* input = "./data/set1/challenge4/c4.txt";
	std::ifstream infile(input);
	std::string line;
	ScoredStrings results;
	while (std::getline(infile, line))
	{
		size_t byteCnt = 0;
		int score = 0;
		unsigned key = 0;
		std::unique_ptr<byte[]> pBytes = crypto_utils::hexToBin(line.c_str(), line.length(), byteCnt);
		std::unique_ptr<char[]> pDecodedStr = crypto_utils::checkSingleByteXORAnsi(pBytes.get(), byteCnt, key, score);
		results.emplace_back(ScoredString(pDecodedStr.get(), score));
	}

	size_t bestIndex = 0, index = 0;
	int bestScore = 0;
	for (auto ss : results) {
		if (ss.Score() > bestScore) {
			bestIndex = index;
			bestScore = ss.Score();
		}
		index++;
	}
	if (bestIndex >= results.size()) {
		return false;
	}

	printf("Best score %d: %s\n", results[bestIndex].Score(), results[bestIndex].StrRef().c_str());

	return true;
}

bool Challenges::Set1Ch5()
{
	// Implement repeating-key XOR
	static const char* pFilename = "./data/set1/challenge5/input.txt";
	static const char* outputFile = "./data/set1/challenge5/encrypted.txt";
	static const char* outputFile2 = "./data/set1/challenge5/decrypted.txt";

	size_t txtBufCnt = 0;
	std::unique_ptr<char[]> pTxt = io_utils::readTextFile(pFilename, txtBufCnt);
	if (!pTxt || txtBufCnt == 0) {
		return false;
	}

	static const byte bKey[] = "ICE";  // TODO - straighten this out ... conversion function?
	std::string key("ICE");
	size_t encBufCnt = 0;
	std::unique_ptr<byte[]> pEncBuf = crypto_utils::encryptRepeatingKey(std::string(pTxt.get()), key, encBufCnt);
	if (!pEncBuf || encBufCnt == 0) {
		return false;
	}
	size_t hexCnt = 0;
	std::unique_ptr<char[]> pHexBuf = crypto_utils::binToHex(pEncBuf.get(), encBufCnt, hexCnt);
	if (hexCnt == 0 || !pHexBuf) {
		return false;
	}

	std::string ostr(pHexBuf.get());
	size_t nWritten = io_utils::writeTextFile(outputFile, ostr.c_str(), ostr.length());

	bool bRc = (nWritten == ostr.length());

	std::unique_ptr<char[]> pRoundTrip = crypto_utils::decryptRepeatingKey(pEncBuf.get(), encBufCnt, bKey, key.length());  // see above
	std::string ostr2(pRoundTrip.get());
	nWritten = io_utils::writeTextFile(outputFile2, pRoundTrip.get(), ostr2.length());
	bRc &= (nWritten == ostr2.length());
	return bRc;
}

bool Challenges::Set1Ch6()
{
	// Break repeating-key XOR

	static const char* pInFile = "./data/set1/challenge6/input.b64";
	size_t b64Cnt = 0;
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileStripCRLF(pInFile, b64Cnt);
	if (!pBase64Buf) {
		return false;
	}

	size_t binCnt = 0;

	std::unique_ptr<byte[]> pBinBytes = crypto_utils::base64ToBin(pBase64Buf.get(), b64Cnt, binCnt);
	const byte* pBinBuf = pBinBytes.get();

	// Overview
	// Compute the most likely key length
	// Break input into KEYLEN-sized blocks
	// Transpose blocks: b1 = first byte of every block, b2 = second byte, etc.
	// Solve each block as if it were single-char XOR (re-use earlier code)
	// Put the single-char solutions together to obtain the key


	// Compute the most likely key length
	unsigned startKeyLen = 2;
	unsigned endKeyLen = 40;
	crypto_utils::KeyLengthRatings keyLengthRatings;
	unsigned keyLength = crypto_utils::getKeyLengthRatings(pBinBuf, startKeyLen, endKeyLen, keyLengthRatings);

	std::cout << "Using best key length = " << keyLength << std::endl;

	//for (const auto& entry : keyLengthRatings) {
	//	std::cout << "Length: " << entry.first << "  Rating: " << entry.second << std::endl;
	//}

	std::unique_ptr<byte[]> spWholeKey = std::unique_ptr<byte[]>(new byte[keyLength]);
	byte* pWholeKey = spWholeKey.get();

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
		std::unique_ptr<char[]> pDecodedStrIgnored = crypto_utils::checkSingleByteXORAnsi(pBytes.get(), bytesInBlock, keyByte, score);
		pWholeKey[keyPos] = keyByte;
	}
	dbg_utils::displayBytes(pWholeKey, keyLength);
	// Decode the whole message with the full computed key and see what it looks like 
	std::unique_ptr<char[]> pCleartext = crypto_utils::decryptRepeatingKey(pBinBuf, binCnt, pWholeKey, keyLength);

	std::cout << "And the decrypted message is:\n";
	std::cout << pCleartext.get();

	return true;
}

bool Challenges::Set1Ch6x()
{
	// Break repeating-key XOR

	static const char* pInFile = "./data/set1/challenge6/input.b64";
	static const char* outputFile2 = "./data/set1/challenge6/decrypted.txt";
	
	size_t base64Cnt = 0;
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileStripCRLF(pInFile, base64Cnt);
	if (!pBase64Buf || !pBase64Buf.get()) {
		return false;
	}

	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBinBytes = crypto_utils::base64ToBin(pBase64Buf.get(), base64Cnt, binCnt);
	const byte* pBinBuf = pBinBytes.get();

	static const byte bKey[] = "ornrn";  // TODO - straighten this out ... conversion function?
	std::string key("ornrn");
	std::unique_ptr<char[]> pRoundTrip = crypto_utils::decryptRepeatingKey(pBinBytes.get(), binCnt, bKey, key.length());  // see above
	std::string ostr2(pRoundTrip.get());
	size_t nWritten = io_utils::writeTextFile(outputFile2, pRoundTrip.get(), ostr2.length());
	bool bRc = (nWritten == ostr2.length());
	std::cout << "Wrote " << nWritten << " bytes to " << outputFile2 << std::endl;
	return bRc;
}
