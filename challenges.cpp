
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
	std::unique_ptr<char[]> pDecodedStr = crypto_utils::checkSingleByteXORAnsi(pTxtBuf.get(), s1.length(), score);

	printf("Decoded string: %s", pDecodedStr.get());

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
		std::unique_ptr<byte[]> pBytes = crypto_utils::hexToBin(line.c_str(), line.length(), byteCnt);
		std::unique_ptr<char[]> pDecodedStr = crypto_utils::checkSingleByteXORAnsi(pBytes.get(), byteCnt, score);
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

	std::unique_ptr<char[]> pRoundTrip = crypto_utils::decryptRepeatingKey(pEncBuf.get(), encBufCnt, key);
	std::string ostr2(pRoundTrip.get());
	nWritten = io_utils::writeTextFileA(outputFile2, pRoundTrip.get(), ostr2.length());
	bRc &= (nWritten == ostr2.length());
	return bRc;
}