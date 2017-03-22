/*
*  Implementation of challenges, Set 3
*/


#include "challenges.h"
#include "utils.h"
#include "aes.h"
#include "backend.h"

using namespace io_utils;


bool Challenges::Set3Ch17()
{
	// From the problem description:
	// This pair of functions approximates AES - CBC encryption as it's deployed serverside in web applications; 
	// the second function models the server's consumption of an encrypted session token, as if it were a cookie. 
	// Also:
	// It is easy to get tripped up on the fact that CBC plaintexts are "padded".
	// Padding oracles have nothing to do with the actual padding on a CBC plaintext.
	// It's an attack that targets a specific bit of code that handles decryption. 
	// You can mount a padding oracle on any CBC block, whether it's padded or not.

	// Just for informational purposes, dump all of the possible input strings managed by the Oracle
	//Backend::DumpAllOracle_3_17();

	byte_string ciphertext;
	byte_string iv;

	static const size_t kBlockSize = 16;  // We'll assume we already figured this out
	static const size_t kBlockNum = 2;    // Will be generalized later - block number we're working on

	Backend::EncryptionOracle_3_17(ciphertext, iv);

	size_t nBytes = ciphertext.length();
	size_t nBlocks = nBytes / kBlockSize;
	std::cout << "Got back cipher text of length: " << nBytes << " bytes == " << nBlocks << " blocks" << std::endl;

	// Find the bytes of P[blockNum]
	// Last byte, we're forming:
	// C1' = C1 XOR Z XOR 0x1
	// Z are the "guesses"

	size_t blockNum = nBlocks - 1;		// blocknum: Block we're currently decrypting
										// (blockNum-1) is the cipher block we're modifying

	std::string plaintext(nBytes, 0x0);
	size_t byteInBlock = kBlockSize - 1;
	byte_string modCipher = ciphertext;  // copy of cipher we'll modify
	
	size_t plainIdx = (blockNum) * kBlockSize + byteInBlock;
	size_t cipherIdx = plainIdx - kBlockSize;
	for (size_t i = 2; i < 0xff; ++i) {
		byte z = static_cast<byte>(i);
		modCipher[cipherIdx] = ciphertext[cipherIdx] ^ z ^ 0x1;

		// debug
		byte C1 = ciphertext[cipherIdx];
		byte C1p = modCipher[cipherIdx];
		// end debug

		bool bPaddingValid = Backend::DecryptionOracle_3_17(modCipher, iv);
		if (bPaddingValid) {
			// We got our valid byte.
			plaintext[plainIdx] = z;
			break;
		}
	}

	std::cout << plaintext << std::endl;

	return true;
}