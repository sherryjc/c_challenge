

#include "backend.h"
#include <unordered_map>
#include <iostream>
#include "aes.h"
#include "utils.h"

using namespace crypto_utils;
using namespace io_utils;

//////////////////////////////////////////////////////////////////////////
//
// Back end functions (Oracles, etc.) for Set 2
//
//////////////////////////////////////////////////////////////////////////

// ------------------------ //
// Set 2 Challenge 11      //
// ------------------------ //
void ModifyInput_2_11(const std::string& inStr, std::string& outStr, size_t blockSz)
{
	// Append 5-10 bytes before and after
	// Counts are random, values fixed
	static const std::string appendStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	size_t nBefore = (crypto_utils::getRandomNumber() % 6) + 5;
	size_t nAfter = (crypto_utils::getRandomNumber() % 6) + 5;

	outStr = appendStr.substr(0, nBefore);
	outStr += inStr;
	outStr += appendStr.substr(nBefore, nAfter);

	// PKCS_7 padding
	size_t inStrTotalLen = inStr.length() + nBefore + nAfter;
	size_t paddedCnt = paddedSize(inStrTotalLen, blockSz);
	size_t nPadBytes = paddedCnt - inStrTotalLen;
	char padByteVal = static_cast<char>(nPadBytes);
	for (size_t i = 0; i < nPadBytes; ++i) {
		outStr += padByteVal;
	}
}

void Backend::EncryptionOracle_2_11(const std::string& inStr, byte_string& outStr)
{
	// 1. Generate a random key (of the same length as the block size)
	// 2. Append bytes before and after the plain text, numbers of bytes chosen randomly
	// 3. Encrypt, choosing ECB or CBC randomly
	// 4. Return the encrypted string (the members of which are actually bytes)

	Aes aes(128);
	aes.SetKey(aes.BlockSize());

	std::string s;
	ModifyInput_2_11(inStr, s, aes.BlockSize());
	aes.SetInput(s);
	aes.InitOutput();  // default to size of input

	aes.SetMode(getRandomBool() ? Aes::CBC : Aes::ECB);
	aes.SetInitializationVector(aes.Mode() == Aes::CBC ? Aes::RANDOM : Aes::ALL_ZEROES);
	aes.Encrypt();
	aes.ResultStr(outStr);
}

// ------------------------ //
// Set 2 Challenge 12       //
// ------------------------ //

static std::unique_ptr<byte[]> ModifyInput_2_12(const byte* pInput, size_t inputLen, size_t blkSize, size_t& resultSz)
{
	// This is the plain text appended by the oracle prior to encryption
	static const char* pFilename = "./data/set2/challenge12/Append.b64";

	size_t base64Cnt = 0;
	std::unique_ptr<char[]>pBase64Buf = readTextFileStripCRLF(pFilename, base64Cnt);
	if (!pBase64Buf || !pBase64Buf.get() || base64Cnt == 0) {
		return nullptr;
	}

	size_t binCnt = 0;
	// No block size arg in the next call, do not apply padding yet
	std::unique_ptr<byte[]> pFileBytes = std::move(base64ToBin(pBase64Buf.get(), base64Cnt, binCnt));

	// Compute padding now that we have all the input
	size_t unpaddedInputSize = inputLen + binCnt;
	size_t paddedCnt = paddedSize(unpaddedInputSize, blkSize);
	std::unique_ptr<byte[]> pOutput(new byte[paddedCnt + 1]);
	byte* pOut = pOutput.get();
	size_t remaining = paddedCnt + 1;  // Remaining bytes in destination buffer
	byteCopy(pOut, remaining, reinterpret_cast<const byte*>(pInput), inputLen);
	remaining -= inputLen;
	pOut += inputLen;
	byteCopy(pOut, remaining, pFileBytes.get(), binCnt);
	remaining -= binCnt;
	pOut += binCnt;
	size_t nPaddingChars = paddedCnt - unpaddedInputSize;
	byte padChar = static_cast<byte>(nPaddingChars);  // PKCS_7
	byteCopyRepeated(pOut, remaining, padChar, nPaddingChars);
	pOut += nPaddingChars;
	*pOut = '\0';
	resultSz = paddedCnt;
	return pOutput;
}

static size_t s_nKeySize = 0;
static byte* s_pKey = nullptr;

void GetSessionKey(size_t blockSzBits, byte*& pKey, size_t& keySz, bool bCreate=false)
{
	// Generate the key the first time we are called in this session and stash it
	// TODO: make a map of "blockSzBits to key struct" to manage multiple keys for multiple block sizes
	// For now, blockSzBits is only ever one value
	// If bCreate is true, generate a new key if one is not already present.
	// If bCreate is false, return what is there (even if null). The blockSzBits argument is
	// currently ignored if bCreate is false.

	if (bCreate && (s_nKeySize == 0 || nullptr == s_pKey)) {
		Aes aes(blockSzBits);
		aes.SetKey(aes.BlockSize());
		s_nKeySize = aes.KeySize();
		s_pKey = new byte[s_nKeySize]{ 0 };
		byteCopy(s_pKey, s_nKeySize, aes.Key(), s_nKeySize);
	}
	pKey = s_pKey;
	keySz = s_nKeySize;
}

std::unique_ptr< byte[] >  Backend::EncryptionOracle_2_12(const byte* pInput, size_t len, size_t& outLen)
{
	// 1. Generate a random key (of the same length as the block size)
	//    - Do this once and re-use the key
	// 2. Append bytes read in from base64 file after the plain text
	// 3. Encrypt using ECB 

	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	aes.SetMode(Aes::ECB);

	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz, true);
	aes.SetKey(pKey, keySz);

	size_t byteCnt = 0;
	std::unique_ptr<byte[]> pBytes = ModifyInput_2_12(pInput, len, aes.BlockSize(), byteCnt);
	aes.SetInput(pBytes.get(), byteCnt, false);  // false: we padded already
	aes.InitOutput();
	aes.Encrypt();
	outLen = 0;
	const byte* pRes = aes.Result(outLen);
	std::unique_ptr<byte[]> pResult(new byte[outLen]);
	byteCopy(pResult.get(), outLen, pRes, outLen);
	return pResult;
}


// ------------------------ //
// Set 2 Challenge 13       //
// ------------------------ //


std::unordered_map<std::string, std::string> s_UserDb;

static void DumpUserDb(bool b)
{
	std::cout << std::endl << "Input string was ";
	if (b) {
		std::cout << "VALID" << std::endl;
	}
	else {
		std::cout << "INVALID" << std::endl;
	}

	std::cout << std::endl << "{" << std::endl;
	bool bFirst = true;
	for (auto& x : s_UserDb) {
		if (!bFirst) {
			std::cout << ',' << std::endl;
		}
		bFirst = false;
		std::cout << "\t" << x.first << ":\t\t\'" << x.second << "\'";
	}
	std::cout << std::endl << "}" << std::endl;
}

static bool ValidKeyChar(char c)
{
	return (isalpha(c) || isdigit(c));
}

static bool ValidValChar(char c)
{
	if (c < 0) {
		return false;
	}
	return (isalpha(c) || isdigit(c) || c == '@' || c == '.');
}

static bool ValidEmailAddr(const std::string& addr)
{
	// Just enforces n@m, i.e. at least one char + @ + at least one char
	bool bGotBefore = false;
	bool bGotAt = false;
	bool bGotAfter = false;

	for (auto c : addr) {
		if (!ValidValChar(c)) {
			return false;
		}
		if (c == '@') {
			// There can only be one '@'
			if (bGotAt) {
				return false;
			}
			bGotAt = true;
		}
		else {
			// Valid, not @
			if (!bGotAt) {
				bGotBefore = true;
			}
			else {
				bGotAfter = true;
			}
		}
	}
	return bGotBefore && bGotAt && bGotAfter;
}

static bool ValidUid(const std::string& addr)
{
	for (auto c : addr) {
		if (!isdigit(c)) {
			return false;
		}
	}
	return true;
}

static bool ParseDbRec(const std::string& str)
{
	// states:
	//  0  looking for key start
	//  1  in key
	//  2  looking for value start
	//  3  in value
	//  Symbol 'V': valid key or value character
	//  x: invalid transition

	//      V    =   &
	//  0:  1    x   x
	//  1:  1    2   x
	//  2:  3    x   x
	//  3:  3    x   0


	int state = 0;
	size_t dbStartSize = s_UserDb.size();
	static const size_t kMAXLEN = 256;
	size_t inputLen = str.length();
	if (inputLen > kMAXLEN) {
		return false;
	}
	size_t pos = 0;
	const char *pC = str.c_str();
	std::string currKey;
	std::string currVal;

	while (pos < inputLen) {
		char c = *pC++;
		pos++;

		switch (state)
		{
		case 0:
			if (ValidKeyChar(c)) {
				currKey += c;
				state = 1;
			}
			else {
				return false;
			}
			break;
		case 1:
			if (ValidKeyChar(c)) {
				currKey += c;
			}
			else if (c == '=') {
				state = 2;
			}
			else {
				return false;
			}
			break;
		case 2:
			if (ValidValChar(c)) {
				currVal += c;
				state = 3;
			}
			else if (c == '=') {
				state = 2;
			}
			else {
				return false;
			}
			break;
		case 3:
			if (ValidValChar(c)) {
				currVal += c;
			}
			else if (c == '&') {
				std::pair<std::string, std::string>entry(currKey, currVal);
				s_UserDb.insert(entry);
				currKey.clear();
				currVal.clear();
				state = 0;
			}
			else {
				return false;
			}
			break;
		default:
			return false;
		}

	}

	if (state == 3) {
		std::pair<std::string, std::string>entry(currKey, currVal);
		s_UserDb.insert(entry);
		state = 0;
	}

	return s_UserDb.size() > dbStartSize;

}

static std::string EncodeProfile(const std::string& emailAddr, const std::string& strUid, const std::string& strRole)
{
	std::string str;
	if (!ValidEmailAddr(emailAddr)) {
		return str;
	}
	if (!ValidUid(strUid)) {
		return str;
	}

	str = "email=";
	str += emailAddr;

	str += "&uid=";
	str += strUid;
	str += "&role=";
	str += strRole;

	return str;
}


byte_string Backend::EncryptionOracle_2_13(const std::string& emailAddr)
{
	// Given an "email address", returns the encrypted encoding string for the user entry
	std::string uid("100");
	std::string user("user");
	std::string encodedProfile = EncodeProfile(emailAddr, uid, user);
	static const byte_string emptyByteStr;
	if (encodedProfile.length() == 0) {
		return emptyByteStr;
	}

	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz, true);
	aes.SetKey(pKey, keySz);
	aes.SetMode(Aes::ECB);
	aes.SetInput(encodedProfile, true);
	aes.Encrypt();

	size_t outLen = 0;
	const byte* pResult = aes.Result(outLen);
	byte_string sRet(pResult, outLen);
	return sRet;
}

bool Backend::Add_User_2_13(const byte_string& encryptedRec)
{
	// Decrypt the input
	// Parse the plaintext and add a user to the Db if valid
	// Print out the change to the db

	bool bUserAdded = false;


	if (s_nKeySize == 0) {
		std::cout << "Session key not found!!" << std::endl;
		return bUserAdded;
	}

	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz);
	aes.SetKey(pKey, keySz);
	aes.SetInput(encryptedRec);
	aes.Decrypt();

	size_t outLen = 0;
	const byte* pResult = aes.Result(outLen);
	std::string profileStr = reinterpret_cast<const char*>(pResult);


	if (profileStr.length() > 0) {
		bUserAdded = ParseDbRec(profileStr);
	}

	if (bUserAdded) {
		DumpUserDb(bUserAdded);
	}

	return bUserAdded;
}

// ------------------------ //
// Set 2 Challenge 14       //
// ------------------------ //

std::unique_ptr< byte[] >  Backend::EncryptionOracle_2_14(const byte* pInput, size_t len, size_t& outLen)
{
	// Like 2_12 with an additional wrinkle
	// 1. Generate a random key (of the same length as the block size)
	//    - Do this once and re-use the key
	// 2. Generate a random count of random bytes and prepend it to the input
	//    This is also done once and cached for the session
	// 3. Append bytes read in from base64 file after the input
	// 4. Encrypt using ECB 
	// So it's:
	// AES-128-ECB(random-prefix || attacker-controller || target-bytes, random-key)


	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	aes.SetMode(Aes::ECB);

	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz, true);
	aes.SetKey(pKey, keySz);

	static const size_t kMaxLen = 50;
	static byte_string s_randomPrefix = getRandomBytes(kMaxLen);
	byte_string strUserInput(pInput, len);
	byte_string firstBytes = s_randomPrefix + strUserInput;

	size_t byteCnt = 0;
	// Re-use the file-appending code from 2_12
	std::unique_ptr<byte[]> pBytes = ModifyInput_2_12(firstBytes.c_str(), firstBytes.length(), aes.BlockSize(), byteCnt);
	aes.SetInput(pBytes.get(), byteCnt, false);  // false: we padded already
	aes.InitOutput();
	aes.Encrypt();
	outLen = 0;
	const byte* pRes = aes.Result(outLen);
	std::unique_ptr<byte[]> pResult(new byte[outLen]);
	byteCopy(pResult.get(), outLen, pRes, outLen);
	return pResult;
}


// ------------------------ //
// Set 2 Challenge 16       //
// ------------------------ //

std::unique_ptr< byte[] >  Backend::EncryptionOracle_2_16(const std::string& strInput, size_t& outLen)
{
	// Prepend first internal string
	// Quote out ";" and "=" characters from the user input
	// Append second internal string
	// Add PKCS7 padding
	// Encrypt - AES, random key

	static const std::string internalS1 = "comment1=cooking%20MCs;userdata=";
	static const std::string internalS2 = ";comment2=%20like%20a%20pound%20of%20bacon";

	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	aes.SetMode(Aes::CBC);
	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz, true);
	aes.SetKey(pKey, keySz);

	// TODO: add pre-pending and appending
	// Just returning the encrypted bytes corresponding to the given input is enough to allow the caller to demonstrate the idea

	aes.SetInput(strInput);
	aes.InitOutput();
	aes.Encrypt();
	outLen = 0;
	const byte* pRes = aes.Result(outLen);
	std::unique_ptr<byte[]> pResult(new byte[outLen]);
	byteCopy(pResult.get(), outLen, pRes, outLen);
	return pResult;
}

std::string Backend::DecryptionOracle_2_16(const byte* pInput, size_t len)
{
	// Decrypt the input string
	// Look for ";admin=true;"

	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz);
	aes.SetKey(pKey, keySz);
	aes.SetInput(pInput, len);
	aes.SetMode(Aes::CBC);
	aes.Decrypt();

	size_t outLen = 0;
	const byte* pResult = aes.Result(outLen);
	std::string sRet(reinterpret_cast<const char*>(pResult), outLen);

	return sRet;
}