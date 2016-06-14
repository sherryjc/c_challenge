
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
	size_t bin1Cnt = 0;
	std::unique_ptr<byte[]> pBinBuf = crypto_utils::hexToBin(pTxtBuf.get(), s1.length(), bin1Cnt);

	byte* pBestArray = nullptr;
	int highestScore = 0;
	byte bestX = 0;
	std::unique_ptr<byte[]> pTestBuf = std::unique_ptr<byte[]>(new byte[bin1Cnt]);
	byte* pTb = pTestBuf.get();
	byte* pInBuf = pBinBuf.get();

	for (size_t key = 0; key <= 0xff; key++) {
		byte xval = key & 0xff;
		for (size_t i = 0; i < bin1Cnt; i++) {
			pTb[i] = (pInBuf[i] ^ xval);
		}
		int score = crypto_utils::rateANSI(pTb, bin1Cnt);
		if (score > highestScore) {
			bestX = xval;
			highestScore = score;
		}
	}
	
	// Re-compute best entry - faster than making copies at each step (?)
	for (size_t i = 0; i < bin1Cnt; i++) {
		pTb[i] = (pBinBuf[i] ^ bestX);
	}
	size_t outCnt = 0;
	std::unique_ptr<char[]> pDecodedStr = crypto_utils::binToTxtANSI(pTb, bin1Cnt, outCnt);

	printf("Decoded string: %s", pDecodedStr.get());

	return true;
}
