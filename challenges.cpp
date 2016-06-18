
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
	static const char* pHexFile2 = "./data/set1/challenge1/roundtrip.hex";

	bool bRc = crypto_utils::convHexToBase64(pHexFile, pOutBase64);
	bool bRc2 = crypto_utils::convBase64ToHex(pOutBase64, pHexFile2);

	return bRc && bRc2;
}

bool Challenges::Set1Ch2()
{
	// test fixed XOR computation
	static const char* input1 = "./data/set1/challenge2/input1.hex";
	static const char* input2 = "./data/set1/challenge2/input2.hex";
	static const char* outputFile = "./data/set1/challenge2/output.hex";

	std::unique_ptr<char[]>pTxtBuf1 = io_utils::readTextFileA(input1);
	std::unique_ptr<char[]>pTxtBuf2 = io_utils::readTextFileA(input2);

	if (!pTxtBuf1 || !pTxtBuf2) {
		return false;
	}
	std::string s1(pTxtBuf1.get());
	std::string s2(pTxtBuf2.get());
	if (s1.length() != s2.length()) {
		io_utils::logError("input lengths differ");
		return false;
	}

	size_t bin1Cnt = 0, bin2Cnt = 0;
	std::unique_ptr<byte[]> pBinBuf1 = crypto_utils::hexToBin(pTxtBuf1.get(), s1.length(), bin1Cnt);
	std::unique_ptr<byte[]> pBinBuf2 = crypto_utils::hexToBin(pTxtBuf2.get(), s2.length(), bin2Cnt);

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
	size_t nWritten = io_utils::writeTextFileA(outputFile, ostr.c_str(), ostr.length());

	return nWritten == ostr.length();
}

bool Challenges::Set1Ch3()
{
	// Break single-byte XOR encryption

	static const char* input = "./data/set1/challenge3/input.hex";
	std::unique_ptr<char[]>pTxtBuf = io_utils::readTextFileA(input);
	if (!pTxtBuf) {
		return false;
	}
	std::string s1(pTxtBuf.get());
	int score = 0;
	unsigned key = 0;
	std::unique_ptr<char[]> pDecodedStr = crypto_utils::checkSingleByteXORAnsi(pTxtBuf.get(), s1.length(), key, score);

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

	std::unique_ptr<char[]> pTxt = io_utils::readTextFileA(pFilename);
	if (!pTxt) {
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
	size_t nWritten = io_utils::writeTextFileA(outputFile, ostr.c_str(), ostr.length());

	bool bRc = (nWritten == ostr.length());

	std::unique_ptr<char[]> pRoundTrip = crypto_utils::decryptRepeatingKey(pEncBuf.get(), encBufCnt, bKey, key.length());  // see above
	std::string ostr2(pRoundTrip.get());
	nWritten = io_utils::writeTextFileA(outputFile2, pRoundTrip.get(), ostr2.length());
	bRc &= (nWritten == ostr2.length());
	return bRc;
}

bool Challenges::Set1Ch6()
{
	// Break repeating-key XOR

	static const char* pInFile = "./data/set1/challenge6/input.b64";
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileA(pInFile);
	if (!pBase64Buf) {
		return false;
	}

	std::string s(pBase64Buf.get());
	size_t binCnt = 0;

	// Note: this strips out CR-LF
	std::unique_ptr<byte[]> pBinBytes = crypto_utils::base64ToBin(pBase64Buf.get(), s.length(), binCnt);
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
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileA(pInFile);
	if (!pBase64Buf) {
		return false;
	}

	std::string s(pBase64Buf.get());
	size_t binCnt = 0;

	// Note: this strips out CR-LF
	std::unique_ptr<byte[]> pBinBytes = crypto_utils::base64ToBin(pBase64Buf.get(), s.length(), binCnt);
	const byte* pBinBuf = pBinBytes.get();

	static const byte bKey[] = "IONEN";  // TODO - straighten this out ... conversion function?
	std::string key("ionen");
	std::unique_ptr<char[]> pRoundTrip = crypto_utils::decryptRepeatingKey(pBinBytes.get(), binCnt, bKey, key.length());  // see above
	std::string ostr2(pRoundTrip.get());
	size_t nWritten = io_utils::writeTextFileA(outputFile2, pRoundTrip.get(), ostr2.length());
	bool bRc = (nWritten == ostr2.length());
	std::cout << "Wrote " << nWritten << " bytes to " << outputFile2 << std::endl;
	return bRc;
}
