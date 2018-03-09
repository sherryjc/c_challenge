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
	Backend::Oracle4* pOracle = Backend::Oracle4::Get(25);
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

