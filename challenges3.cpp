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

	if (nBlocks < 2) {
		std::cout << "This method won't work for block sizes less than 2" << std::endl;
		return false;
	}

	// we'll gather all of the decrypted plaintext into this string
	std::string plaintext(nBytes, 0x0);

	for (size_t blkNum = nBlocks-1; blkNum >0; --blkNum) {

		// Copy of the ciphertext we'll be modifying
		byte_string modCipher = ciphertext.substr(0, (blkNum+1)*kBlockSize);
		byte z[kBlockSize]{ 0 };
		size_t plainBlockStart = (blkNum)* kBlockSize;
		size_t cipherBlockStart = plainBlockStart - kBlockSize;

		// Work through each byte of the current block
		for (size_t offset = 1; offset <= kBlockSize; ++offset) {

			size_t activeByteIdx = kBlockSize - offset;
			byte padChar = static_cast<byte>(offset);

			// Set the bytes in the cipher that we have already figured out
			for (size_t j = kBlockSize - 1; j > activeByteIdx; --j) {
				modCipher[cipherBlockStart + j] = ciphertext[cipherBlockStart + j] ^ z[j] ^ padChar;
			}
			// Cover the case of a false positive match of the test pad character.
			// If the "valid" byte == the pad char, proceed on to see if there are
			// any other matches and only use the pad char if not.
			byte padMatch = 0;
			// Now try all values for the byte 'z' of the cipher we are varying
			size_t cipherIdx = cipherBlockStart + activeByteIdx;
			for (size_t i = 1; i < 0xff; ++i) {

				z[activeByteIdx] = static_cast<byte>(i);
				modCipher[cipherIdx] = ciphertext[cipherIdx] ^ z[activeByteIdx] ^ padChar;

				bool bPaddingValid = Backend::DecryptionOracle_3_17(modCipher, iv);
				if (bPaddingValid) {
 					if (z[activeByteIdx] == padChar) {
 						padMatch = padChar;
					}
					else {
						// We got our valid byte.
						plaintext[plainBlockStart + activeByteIdx] = z[activeByteIdx];
						padMatch = 0;
						break;
					}
				}
			}
 			if (padMatch != 0) {
 				plaintext[plainBlockStart + activeByteIdx] = padMatch;
				z[activeByteIdx] = padMatch;
 				padMatch = 0;
 			}
		}
	}

	//std::cout << "Plaintext before padding stripped:" << std::endl;
	//std::cout << plaintext << std::endl;

	std::string strippedPlaintext;
	crypto_utils::stripPKCS7Padding(plaintext, strippedPlaintext, kBlockSize);
	std::cout << "Plaintext after padding stripped:" << std::endl;
	std::cout << strippedPlaintext << std::endl;

	return true;
}