/*
*  Implementation of challenges, Set 4
*/


#include "challenges.h"
#include "utils.h"
#include "aes.h"
#include "backend.h"
#include "RNG.h"

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
