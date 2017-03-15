
/*
 *  Implementation of challenges, set 1
 */


#include "challenges.h"
#include "utils.h"
#include "aes.h"

using namespace io_utils;

bool Challenges::Set1Ch1()
{
	// Convert hex to base64 and back
	static const char* pHexFile = "./data/set1/challenge1/input.hex";
	static const char* pOutBase64 = "./data/set1/challenge1/outputB64.hex";
	static const char* pHexFileOut = "./data/set1/challenge1/roundtrip.hex";

	// Original input file from the Cryptopals web site
	bool bRc = crypto_utils::convHexToBase64(pHexFile, pOutBase64);
	bRc &= crypto_utils::convBase64ToHex(pOutBase64, pHexFileOut);
	
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

	if (!pTxtBuf1 || buf1Cnt == 0 || !pTxtBuf2 || buf2Cnt == 0) {
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
	std::unique_ptr<char[]> pDecodedStr = crypto_utils::checkSingleByteXORAnsiH(pTxtBuf.get(), txtBufCnt, key, score);

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
	// Correct key length is 29 but that is not even close to being rated the best length
	crypto_utils::KeyLengthRatings keyLengthRatings;
	unsigned bestKeyLength = crypto_utils::getKeyLengthRatings(pBinBuf, startKeyLen, endKeyLen, keyLengthRatings);

	std::cout << "Computed best key length = " << bestKeyLength << std::endl;

	std::cout << "All computed key lengths:" << std::endl;
	for (const auto& entry : keyLengthRatings) {
		std::cout << "Length: " << entry.first << "  Rating: " << entry.second << std::endl;
	}

	unsigned startTryKL = 29; // 2;
	unsigned endTryKL = 29;  // 40;
	for (unsigned keyLength = startTryKL; keyLength <= endTryKL; keyLength++) {
		std::unique_ptr<byte[]> spWholeKey = std::unique_ptr<byte[]>(new byte[keyLength]);
		byte* pKey = spWholeKey.get();

		std::unique_ptr<char[]> pCleartext = crypto_utils::decodeUsingFixedKeyLength(pBinBuf, binCnt, pKey, keyLength);

		std::cout << "\n\nDecrypted with keyLength " << keyLength << std::endl;
		dbg_utils::displayBytes("Key bytes: ", pKey, keyLength);

		std::cout << pCleartext.get();
	}

	return true;
}

bool Challenges::Set1Ch6x()
{
	// Break repeating-key XOR

	static const char* pInFile = "./data/set1/challenge6/input.b64";
	static const char* outputFile2 = "./data/set1/challenge6/decrypted.txt";
	
	size_t base64Cnt = 0;
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileStripCRLF(pInFile, base64Cnt);
	if (!pBase64Buf || !pBase64Buf.get() || base64Cnt == 0) {
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

bool Challenges::Set1Ch7()
{
	// AES in ECB mode
	// In ECB mode, each block is just encrypted with the same key. Not secure, of course!

	static const char* pInFile = "./data/set1/challenge7/input.txt";
	static const char* pOutputFile = "./data/set1/challenge7/decrypted.txt";
	static const char* outputFileHex = "./data/set1/challenge7/decryptedHex.txt";
	static const char* inputFileHex = "./data/set1/challenge7/encryptedHex.txt";


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

	Aes aes(128);
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

bool Challenges::Set1Ch7x()
{
	// Write out a hex file - the challenge7 file decrypted by an AES 128 ECB web-site tool 

	static const char* outputFile = "./data/set1/challenge7/decryptedWebSite.txt";
	static const char* inputHex = "./data/set1/challenge7/decryptedHexWebSite.txt";

	size_t bufCnt = 0;
	std::unique_ptr<char[]>pTxtBuf = io_utils::readTextFileStripCRLF(inputHex, bufCnt);

	if (!pTxtBuf || bufCnt == 0) {
		std::cout << "Error reading input hex file\n";
		return false;
	}

	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBinBuf = crypto_utils::hexToBin(pTxtBuf.get(), bufCnt, binCnt);

	if (binCnt == 0 || !pBinBuf) {
		std::cout << "Error converting hex to bin\n";
		return false;
	}

	size_t outCnt = 0;
	std::unique_ptr<char[]> pOutTxtBuf = crypto_utils::binToTxtANSI(pBinBuf.get(), binCnt, outCnt);
	std::string ostr(pOutTxtBuf.get());
	size_t nWritten = io_utils::writeTextFile(outputFile, ostr.c_str(), ostr.length());
	std::cout << "Wrote " << nWritten << " text characters to " << outputFile << std::endl;

	return true;
}

bool Challenges::Set1Ch7y()
{
	// Tests a simple round-trip encryption-decryption of text of our choosing
	static const char* pInFile = "./data/set1/challenge7/test_input.txt";
	static const char* pEncFile = "./data/set1/challenge7/test_input_enc.bin";
	static const char* pOutFile = "./data/set1/challenge7/test_input_dec.txt";

	static const byte bKey[] = "YELLOW SUBMARINE";
	std::string key("YELLOW SUBMARINE");

	Aes aes(128);
	aes.SetKey(bKey, key.length());
	size_t nRead = aes.Read(pInFile, FileType::ASCII);
	std::cout << "Read " << nRead << " ASCII characters (plus possible padding) from plaintext file " << pEncFile << std::endl;
	aes.Encrypt();
	size_t nWritten = aes.Write(pEncFile, FileType::BINARY);

	std::cout << "Wrote " << nWritten << " binary characters to encrypted file " << pEncFile << std::endl;

	Aes aes2(128);
	aes2.SetKey(bKey, key.length());
	aes2.Read(pEncFile, FileType::BINARY);
	aes2.Decrypt();
	size_t nWritten2 = aes2.Write(pOutFile, FileType::BINARY);

	std::cout << "Wrote " << nWritten2 << " binary characters to decrypted file " << pOutFile << std::endl;

	return nWritten == nWritten2;
}

bool Challenges::Set1Ch7z()
{
	// Read in Base64 generated by web site (encryption of my test plaintext)
	// Write out binary
	// Read binary and decrypt it

	//static const char* pInFile = "./data/set1/challenge7/AES_shortTest2_B64.txt";
	static const char* pEncBinFile = "./data/set1/challenge7/Simple1.bin";
	static const char* pDecBinFile = "./data/set1/challenge7/Simple1Dec.bin";

#if 0
	size_t base64Cnt = 0;
	std::unique_ptr<char[]>pBase64Buf = io_utils::readTextFileStripCRLF(pInFile, base64Cnt);
	if (!pBase64Buf || !pBase64Buf.get() || base64Cnt == 0) {
		return false;
	}

	size_t binCnt = 0;
	std::unique_ptr<byte[]> pBinBytes = crypto_utils::base64ToBin(pBase64Buf.get(), base64Cnt, binCnt);
	const byte* pBinBuf = pBinBytes.get();

	size_t nWritten = io_utils::writeBinFile(pEncBinFile, pBinBuf, binCnt);
	bool bRc = (nWritten == binCnt);
	std::cout << "Wrote " << nWritten << " bytes to " << pEncBinFile << std::endl;
#endif 

	static const byte bKey[] = "YELLOW SUBMARINE";
	std::string key("YELLOW SUBMARINE");

	Aes aes2(128);
	aes2.SetKey(bKey, key.length());
	aes2.Read(pEncBinFile, FileType::BINARY);
	aes2.Decrypt();
	size_t nWritten2 = aes2.Write(pDecBinFile, FileType::BINARY);

	std::cout << "Wrote " << nWritten2 << " binary characters to decrypted file " << pDecBinFile << std::endl;
	return true;
}

bool Challenges::Set1Ch8()
{
	// This challenge: detect ECB
	// We just check for duplicate blocks in the cipher text. If we are
	// lucky, there will have been duplicate blocks of plain text (which
	// will show up as duplicates in the cipher text in ECB).
	static const char* pInFile = "./data/set1/challenge8/input_hex.txt";

	size_t hexCharCnt = 0;
	std::unique_ptr<char[]> pHex = io_utils::readTextFile(pInFile, hexCharCnt);
	if (!pHex || !pHex.get() || hexCharCnt == 0) {
		return false;
	}
	std::cout << "Read " << hexCharCnt << " ASCII characters from hex file " << pInFile << std::endl;
	std::vector<std::string> vec;
	io_utils::separateStrings(vec, pHex.get(), hexCharCnt);
	std::vector<size_t> results_vec;
	
	std::cout << "Checking " << vec.size() << " strings\n";
	
	static const size_t kBlockSize = 32; // 16 bytes, represented by 32 hex characters 
	size_t cnt = 0;
	for (auto str : vec) {
		bool b = crypto_utils::checkDuplicateBlocks(str, kBlockSize);
		if (b) {
			results_vec.push_back(cnt);
			std::cout << "String " << cnt << " has duplicate block\n";
			std::cout << "[[ " << str << " ]]";
		}
		cnt++;
	}

	std::cout << "Found " << results_vec.size() << " strings with duplicated blocks";

	return true;
}

bool Challenges::Set1Ch8a()
{
	// Chosen plaintext, examine encrypted bytes
	static const char* pInFile = "./data/set1/challenge8/test_input.txt";
	static const char* pEncFile = "./data/set1/challenge8/test_input_enc.hex";

	static const byte bKey[] = "YELLOW SUBMARINE";
	std::string key("YELLOW SUBMARINE");

	Aes aes(128);
	aes.SetKey(bKey, key.length());
	size_t nRead = aes.Read(pInFile, FileType::ASCII);
	std::cout << "Read " << nRead << " ASCII characters (plus possible padding) from plaintext file " << pEncFile << std::endl;
	aes.Encrypt();

	size_t nWritten = aes.Write(pEncFile, FileType::HEX);

	std::cout << "Wrote " << nWritten << " hex characters to encrypted file " << pEncFile << std::endl;

	return nWritten > 0;
}

