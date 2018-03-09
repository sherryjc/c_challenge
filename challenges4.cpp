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
	// same input data as Set1Ch7
	static const char* pInFile = "./data/set4/challenge25/input.b64";
	static const byte bKey[] = "YELLOW SUBMARINE";
	static const byte_string bHack = reinterpret_cast<byte*>("YOU ARE TOAST!");

	// The recovered plaintext is now the input for the rest of the exercise
	Aes aes2(128);
	aes2.SetKey(bKey, _countof(bKey) - 1);
	aes2.Read(pInFile, FileType::BASE64);
	aes2.Decrypt();
	byte_string inputStr;
	aes2.ResultStr(inputStr);

	static const size_t kBlockSz = 16;
	Aes aes(kBlockSz * 8);
	aes.SetMode(Aes::CTR);
	aes.SetKey(kBlockSz);		// Generate a random key

	size_t streamLength = inputStr.length();
	std::unique_ptr<byte[]> pCipher(new byte[streamLength]);
	aes.ResetStream();
	aes.EncryptStream(inputStr.c_str(), streamLength, pCipher.get(), streamLength);

#if 1   // Getting it working
	// Dump the recovered plaintext (knowing the key)
	std::cout << inputStr.c_str() << std::endl;
	std::cout << "###############################" << std::endl;

	_EditStream(pCipher.get(), streamLength, aes.Key(), aes.KeySize(), 100, bHack);

	std::unique_ptr<byte[]> pModified(new byte[streamLength+1]);
	aes.ResetStream();
	aes.DecryptStream(pCipher.get(), streamLength, pModified.get(), streamLength);

	// Display the recovered plaintext with our modification to show it worked
	byte* pDisplay = pModified.get();
	pDisplay[streamLength] = '\0';
	std::cout << pDisplay << std::endl;
	std::cout << "###############################" << std::endl;
#endif

	// Now imagine the edit function was exposed by means of an API call, but
	// the key and original plaintext were not revealed.
	// Show how the original plaintext could be recovered.

	// We already modified starting at offset 100 above
	// Let's just recover the first block as a proof-of-concept

	// Save the original cipher text
	byte origCT[kBlockSz] = { 0 };
	io_utils::byteCopy(origCT, _countof(origCT), pCipher.get(), kBlockSz);

	// Edit in our chosen text and read back the encrypted result
	static const byte_string modPT = reinterpret_cast<byte*>("0123456789ABCDEF");

	// The user doesn't actually know aes.Key() and KeySize(), the oracle would keep them.
	// This just shortcuts creating a new back-end function.
	_EditStream(pCipher.get(), streamLength, aes.Key(), aes.KeySize(), 0, modPT);

	byte modCT[kBlockSz] = { 0 };
	io_utils::byteCopy(modCT, _countof(modCT), pCipher.get(), kBlockSz);

	// Recover the key: key = plaintext XOR ciphertext
	byte key[kBlockSz];
	crypto_utils::xorBlock(key, modPT.c_str(), modCT, _countof(key));

	// Now recover the original plaintext = key XOR original-ciphertext
	byte origPT[kBlockSz + 1];
	crypto_utils::xorBlock(origPT, origCT, key, kBlockSz);
	origPT[kBlockSz] = '\0';

	std::cout << "First block of recovered plain text" << std::endl;
	std::cout << origPT << std::endl;
	return true;
}

