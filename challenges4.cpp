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
						size_t offset, std::string replacement)
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
	static const std::string bHack = "YOU ARE TOAST!";

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

	std::cout << inputStr.c_str() << std::endl;

	_EditStream(pCipher.get(), streamLength, aes.Key(), aes.KeySize(), 100, bHack);

	std::unique_ptr<byte[]> pModified(new byte[streamLength+1]);
	aes.ResetStream();
	aes.DecryptStream(pCipher.get(), streamLength, pModified.get(), streamLength);

	byte* pDisplay = pModified.get();
	pDisplay[streamLength] = '\0';
	std::cout << pDisplay << std::endl;

	return true;
}

