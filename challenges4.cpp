/*
*  Implementation of challenges, Set 4
*/


#include "challenges.h"
#include "utils.h"
#include "aes.h"
#include "backend.h"
#include "RNG.h"
#include "sha1.h"

using namespace io_utils;
using namespace crypto_utils;

// --------------------
//   Set4 Ch25
// --------------------

static void _EditStream(byte* pCiphertext, size_t cipherLen,
						const byte* pKey, size_t keyLen,
						size_t offset, byte_string replacement)
{
	static const size_t kBlockSz = 16;


	Aes aes(kBlockSz * 8);
	aes.SetMode(Aes::CTR);
	aes.SetKey(pKey, keyLen);		
	aes.ReplaceStreamBytes(pCiphertext, cipherLen, offset, replacement);

}

bool Challenges::Set4Ch25()
{
	constexpr int kThisTestCaseNr = 25;
	Backend::Oracle4* pOracle = Backend::Oracle4::Get(kThisTestCaseNr);
	if (!pOracle) return false;

	// Test code (this wouldn't be exposed by the real oracle)
	// Strings to test the stream edit function
	static const byte_string bHack = reinterpret_cast<byte*>("YOU ARE TOAST!");
	static const byte_string bHack2 = { 0xd0, 0x96, 0xd0, 0x95, 0xd0, 0x9b, 0xd0, 0x90, 0xd0, 0x9d, 0xd0, 0x9d, 0xd0, 0xac, 0xd0, 0x86, 0xd0, 0x98 };
	pOracle->DumpDatabase();
	std::cout << "###############################" << std::endl;
	pOracle->EditEncryptedStream(100, bHack);
	pOracle->EditEncryptedStream(120, bHack2);
	pOracle->DumpDatabase();
	std::cout << "###############################" << std::endl;

	// Now the actual exercise

	// The oracle exposes the edit function by means of an API call
	// It does not reveal the key and original plaintext.
	// Show how the original plaintext can be recovered.


	// Save the original cipher text
	size_t encSz = pOracle->GetEncryptedDataSize();
	std::unique_ptr<byte[]> pOrigCT(new byte[encSz]);
	pOracle->GetEncryptedData(pOrigCT.get(), encSz);


	// Edit in our chosen text and read back the encrypted result
	// If this were all 0's we'd save an XOR step below (?)
	// Let's just recover the first block as a proof-of-concept
	constexpr size_t kBlockSz = 16;
	static const byte_string modPT = reinterpret_cast<byte*>("0123456789ABCDEF");
	pOracle->EditEncryptedStream(0, modPT);

	// Encrypted stream should still be the same size, but check
	encSz = pOracle->GetEncryptedDataSize();
	std::unique_ptr<byte[]> pModCT(new byte[encSz]);
	pOracle->GetEncryptedData(pModCT.get(), encSz);

	// Recover the key: key = plaintext XOR ciphertext
	byte key[kBlockSz];
	crypto_utils::xorBlock(key, modPT.c_str(), pModCT.get(), _countof(key));

	// Now recover the original plaintext = key XOR original-ciphertext
	byte origPT[kBlockSz + 1];
	crypto_utils::xorBlock(origPT, pOrigCT.get(), key, kBlockSz);
	origPT[kBlockSz] = '\0';

	std::cout << "First block of recovered plain text" << std::endl;
	std::cout << origPT << std::endl;
	return true;
}

bool Challenges::Set4Ch26()
{
	constexpr int kThisTestCaseNr = 26;
	Backend::Oracle4* pOracle = Backend::Oracle4::Get(kThisTestCaseNr);
	if (!pOracle) return false;

	byte_string strInput1 = reinterpret_cast<byte *>("AAAAAAAAAAAAAAAAAAAAAA");
	byte_string strInput2 = reinterpret_cast<byte *>("BAAAAAAAAAAAAAAAAAAAAA");

	pOracle->EnterQuery(strInput1);
	size_t encSz1 = pOracle->GetEncryptedDataSize();
	std::unique_ptr<byte[]> upCT1(new byte[encSz1 + 1]);
	byte* pCT1 = upCT1.get();
	pOracle->GetEncryptedData(pCT1, encSz1);

	// Debug only, wouldn't be available in the real oracle
	std::cout << std::endl << "##########################" << std::endl;
	pOracle->DumpDatabase();
	std::cout << std::endl << "##########################" << std::endl;

	// See where the second test string's encryption differs from the first.
	// That's the point where we'll insert our modified encrypted text.
	pOracle->EnterQuery(strInput2);
	size_t encSz2 = pOracle->GetEncryptedDataSize();
	std::unique_ptr<byte[]> upCT2(new byte[encSz2 + 1]);
	byte* pCT2 = upCT2.get();
	pOracle->GetEncryptedData(pCT2, encSz2);

	size_t minSz = encSz1 < encSz2 ? encSz1 : encSz2;  // These should be the same

	size_t diffIdx = io_utils::nBytesCompare(pCT1, pCT2, minSz) + 1;  // Move one byte forward to leave one character of the user data before our insertion

	if (diffIdx >= minSz)
	{
		std::cout << "The strings encrypted to the same bytes??" << std::endl;
		return false;
	}

	// The bits that need to change in each cipher text character are the bits that differ
	// between the original input value that encrypted to C1 and the desired "input" value.
	// C1' is the altered C1:
	// C1'[j] = C1[j] XOR (origInp[j] XOR desiredInp[j]);
	static const byte_string desiredStr = reinterpret_cast<byte*>(";admin=true;comment=");
	if (diffIdx + desiredStr.length() > encSz1)
	{
		std::cout << "Problem with length calculation - not enough room" << std::endl;
		return false;
	}

	for (size_t i = 0; i < desiredStr.length(); ++i) {
		pCT1[diffIdx++] ^= (desiredStr[i] ^ strInput1[i]);
	}

	// Set the modified cipher text on the oracle
	pOracle->SetEncryptedData(pCT1);

	std::cout << "Admin rights: ";
	std::string result = (pOracle->QueryAdmin() ? "TRUE" : "FALSE");
	std::cout << result << std::endl;

	// Debug only
	std::cout << std::endl << "##########################" << std::endl;
	pOracle->DumpDatabase();
	std::cout << std::endl << "##########################" << std::endl;

	return true;

}

bool Challenges::Set4Ch27()
{
	// For this challenge, we set the IV = Key.
	// Encrypting P1 P2 P3 is thus:
	// C0 = IV = Key
	// C1 = ENC(P1 XOR C0) 
	// C2 = ENC(P2 XOR C1) 
	// C3 = ENC(P3 XOR C2) 
	//
	// Forming C1 0 C1 and decrypting to Q1 Q2 Q3:
	// C0 = IV = Key
	// Q1 = DEC(C1) XOR C0
	// Q2 = DEC(0) XOR C1
	// Q3 = DEC(C1) XOR 0
	//
	// Then form Q1 XOR Q3
	// Q1 XOR Q3 = DEC(C1) XOR Key XOR DEC(C1) = Key 

	constexpr int kThisTestCaseNr = 27;
	Backend::Oracle4* pOracle = Backend::Oracle4::Get(kThisTestCaseNr);
	if (!pOracle) return false;

	byte_string inputStr = reinterpret_cast<byte*>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
	pOracle->SetPlaintext(inputStr);

	pOracle->Encrypt_Ch27();

	// Get the cipher text 
	byte_string cipherText;
	pOracle->GetCiphertext(cipherText);

	// Modify the cipher text and set it as the current command
	// C_1, C_2, C_3 -> C_1, 0, C_1
	constexpr int nBlockSize = 16;
	constexpr int nMin = 3 * nBlockSize;
	if (cipherText.length() < nMin)
	{
		std::cout << "The encrypted string that was read is not long enough" << std::endl;
		return false;
	}
	
	byte_string c1 = cipherText.substr(0, nBlockSize);
	byte rawArray[nMin]{ 0 };
	byte* pBytes = rawArray;
	io_utils::byteCopy(pBytes, _countof(rawArray), c1.c_str(), nBlockSize);
	// Note we are leaving a hole in the middle block here so those bytes will remain == 0
	io_utils::byteCopy(pBytes + 2 * nBlockSize, _countof(rawArray) - 2 * nBlockSize, c1.c_str(), nBlockSize);

	pOracle->SetRawCiphertext(pBytes, nMin);

	byte_string errorStr;
	pOracle->Validate_Ch27(errorStr);
	if (errorStr.length() > 0)
	{
		std::cout << "Input string was flagged: " << std::endl;
		std::cout << errorStr.c_str() << std::endl;

		// Now use this error string to recover the key
		byte Q1[nBlockSize] = { 0 };
		byte* pQ1 = Q1;
		const byte* pErrStr = errorStr.c_str();
		io_utils::byteCopy(pQ1, nBlockSize, pErrStr, nBlockSize);
		byte Q3[nBlockSize] = { 0 };
		byte* pQ3 = Q3;
		io_utils::byteCopy(pQ3, nBlockSize, pErrStr + 2 * nBlockSize, nBlockSize);
		byte recoveredKey[nBlockSize + 1] = { 0 };
		byte* pRK = recoveredKey;
		for (int i = 0; i < nBlockSize; ++i)
		{
			*pRK++ = *pQ1++ ^ *pQ3++;
		}
		*pRK = '\0';
		std::cout << "The recovered key = " << recoveredKey << std::endl;
	}
	else
	{
		std::cout << "The input string was valid" << std::endl;
	}

	return true;
}

static void _DisplaySHA1(const byte* pBytes, size_t len)
{
	byte result[kDigestSize + 1];
	SHA1(result, pBytes, len);
	dbg_utils::displayHex(result, kDigestSize);
}


bool Challenges::Set4Ch28()
{
	SHA1_Test_RunAll();

	const byte_string string2 = reinterpret_cast<byte*>("abc");
	const byte_string string3 = reinterpret_cast<byte*>("Abc");
	const byte_string string4 = { 0xd0, 0x96, 0xd0, 0x95, 0xd0, 0x9b, 0xd0, 0x90, 0xd0, 0x9d, 0xd0, 0x9d, 0xd0, 0xac, 0xd0, 0x86, 0xd0, 0x98 };

	_DisplaySHA1(string2.c_str(), string2.length());
	_DisplaySHA1(string3.c_str(), string3.length());
	_DisplaySHA1(string4.c_str(), string4.length());

	const byte_string key1 = reinterpret_cast<byte*>("Salt3743");
	const byte_string key2 = reinterpret_cast<byte*>("Salt2185");

	byte_string string_k1_4 = key1 + string4;
	byte_string string_k2_4 = key2 + string4;
	_DisplaySHA1(string_k1_4.c_str(), string_k1_4.length());
	_DisplaySHA1(string_k2_4.c_str(), string_k2_4.length());

	return true;
}

static bool _ComputeMDPaddedMsg(const byte_string& msg, byte_string& paddedMsg, bool bIncludeLen)
{
	// Does the full pre-processing as described in the SHA-1 wiki page.
	// Append '1' bit by adding 0x80 if the message length is a multiple of 8 bits
	// Append 0 <= k < 512 bits = 64 bytes of 0's s.t. resulting bit length is 448 (mod 512)
	// Then append the original message length as a 64-bit BE integer.

	int64_t origMLBits = msg.length() * 8;

	paddedMsg = msg;
	// Since our messages are in bytes, we will always add the first 0x80
	paddedMsg += (byte)0x80;

	size_t paddedMsgByteLen = paddedMsg.length();
	size_t paddedMsgBitLen = paddedMsgByteLen * 8;
	
	int pmblMod512 = paddedMsgBitLen % 512;
	int zeroBits = 448 - pmblMod512;
	if (zeroBits < 0) zeroBits += 512;

	if (zeroBits % 8)
	{
		return false;
	}
	int zeroBytes = (zeroBits / 8);
	while (zeroBytes-- > 0)
	{
		paddedMsg += (byte)0x0;
	}

	// Prepare the original message length bytes
	byte oml[sizeof(int64_t)]{ 0 };
	io_utils::int64ToBytesBE(origMLBits, oml, sizeof(oml));

	for (size_t ii = 0; ii < sizeof(oml); ++ii)
	{
		paddedMsg += oml[ii];
	}

	paddedMsgBitLen = paddedMsg.length() * 8;
	return (paddedMsgBitLen % 512) ? false : true;
}

static void _ComputeMDPadding(const byte_string& msg, byte_string& padding)
{
	// Just appends the original message length as a 64-bit BE integer.
	padding.clear();

	int64_t origMLBits = msg.length() * 8;

	// Prepare the original message length bytes
	byte oml[sizeof(int64_t)]{ 0 };
	io_utils::int64ToBytesBE(origMLBits, oml, sizeof(oml));

	for (size_t ii = 0; ii < sizeof(oml); ++ii)
	{
		padding += oml[ii];
	}
}

bool Challenges::Set4Ch29()
{

	const byte_string origString = reinterpret_cast<byte*>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123");
	byte_string padding;
	_ComputeMDPadding(origString, padding);

	// To verify we are using the same padding, we need the padded string minus the length bytes at the end
	_DisplaySHA1(origString.c_str(), origString.length());
	//_DisplaySHA1(paddedMsgMinusLength.c_str(), paddedMsgMinusLength.length());
	dbg_utils::displayHex(padding);

	return true;
}
