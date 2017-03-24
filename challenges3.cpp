/*
*  Implementation of challenges, Set 3
*/


#include "challenges.h"
#include "utils.h"
#include "aes.h"
#include "backend.h"
#include "RNG.h"

using namespace io_utils;
using namespace crypto_utils;


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

bool Challenges::Set3Ch18()
{
	//	key = YELLOW SUBMARINE
	//	nonce = 0
	//	format = 64 bit unsigned little endian nonce,
	//	64 bit little endian block count(byte count / 16)

	static const size_t kBlockSz = 16;
	std::string inpB64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
	static const byte bKey[] = "YELLOW SUBMARINE";

	size_t outCnt = 0;
	std::unique_ptr<byte[]> pBin = crypto_utils::base64ToBin(inpB64.c_str(), inpB64.length(), outCnt);
	byte* pBytes = pBin.get();

	Aes aes(128);
	aes.SetMode(Aes::CTR);
	aes.SetKey(bKey, _countof(bKey)-1);

	std::unique_ptr<byte[]> pOutput(new byte[outCnt]);
	byte* pOut = pOutput.get();
	aes.DecryptStream(pBytes, outCnt, pOut, outCnt);

	std::string display(reinterpret_cast<char *>(pOut), outCnt);
	std::cout << "Result:" << std::endl;
	std::cout << display << std::endl;

	static const byte plaintext1[] =	
		"This is a stream of boring and content-free plain text that \n"
		"will not make for interesting reading for anybody,\n"
		"but it may just be the test that breaks the code.\n";

	byte ciphertext1[_countof(plaintext1)]{ 0 };
	byte plaintext2[_countof(plaintext1)]{ 0 };

	// Generate a random key
	aes.SetKey(kBlockSz);
	aes.ResetStream();
	aes.EncryptStream(plaintext1, _countof(plaintext1)-1, ciphertext1, _countof(ciphertext1) - 1);
	aes.ResetStream();
	aes.DecryptStream(ciphertext1, _countof(ciphertext1) - 1, plaintext2, _countof(plaintext2) - 1);

	std::cout << "Before:" << std::endl;
	std::cout << plaintext1 << std::endl;

	std::cout << "Encrypted:" << std::endl;
	std::cout << ciphertext1 << std::endl;

	std::cout << "After:" << std::endl;
	std::cout << plaintext2 << std::endl;

	return true;
}

bool Challenges::Set3Ch19()
{
	static const std::string inputStrings[] = {
	"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
	"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
	"U2hlIHJvZGUgdG8gaGFycmllcnM/",
	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
	"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
	"VHJhbnNmb3JtZWQgdXR0ZXJseTo="
	};

	static const size_t kBlockSz = 16;
	Aes aes(kBlockSz*8);
	aes.SetMode(Aes::CTR);
	aes.SetKey(kBlockSz);		// Generate a random key

	//std::vector<std::string> vResults;

	for (auto str : inputStrings) {
		size_t binInputCnt = 0;
		std::unique_ptr<byte[]> pBin = crypto_utils::base64ToBin(str.c_str(), str.length(), binInputCnt);
		byte* pBytes = pBin.get();

		std::unique_ptr<byte[]> pCipher(new byte[binInputCnt]);
		byte* pCiph = pCipher.get();
		aes.ResetStream();
		aes.EncryptStream(pBytes, binInputCnt, pCiph, binInputCnt);
		dbg_utils::displayHex(pCiph, binInputCnt);
		//vResults.emplace_back(std::string(reinterpret_cast<char *>(pCiph), binInputCnt));
	}


	return true;
}


bool Challenges::Set3Ch20()
{
	// Each line of this file is to be treated as a separate b64-encoded string
	static const char* pInFile = "./data/set3/challenge20/inputs.b64";

	size_t charCnt = 0;
	std::unique_ptr<char[]> pText = io_utils::readTextFile(pInFile, charCnt);
	if (!pText || !pText.get() || charCnt == 0) {
		return false;
	}
	std::vector<std::string> vecInpB64Strings;
	io_utils::separateStrings(vecInpB64Strings, pText.get(), charCnt);

	std::vector<byte_string> vEncryptedStrings;

	static const size_t kBlockSz = 16;
	Aes aes(kBlockSz * 8);
	aes.SetMode(Aes::CTR);
	aes.SetKey(kBlockSz);  // Generate a random key

	for (auto str : vecInpB64Strings) {
		size_t binInputCnt = 0;
		std::unique_ptr<byte[]> pBin = crypto_utils::base64ToBin(str.c_str(), str.length(), binInputCnt);
		byte* pInBytes = pBin.get();
		// Could save vector of pInBytes to see what the answers are

		// Just encrypt the input text and save it in a vector
		std::unique_ptr<byte[]> pCipher(new byte[binInputCnt]);
		byte* pCiph = pCipher.get();
		aes.ResetStream();
		aes.EncryptStream(pInBytes, binInputCnt, pCiph, binInputCnt);
		vEncryptedStrings.emplace_back(byte_string(pCiph, binInputCnt));
	}

	// See what the smallest ciphertext string is minCipherLen
	size_t minCipherLen = 100000000;

	for (auto cs : vEncryptedStrings) {
		if (cs.length() < minCipherLen) {
			minCipherLen = cs.length();
		}
	}

	// Concatenate the first minCipherLen bytes from each cipher string into one long buffer
	// First make sure there is no size limitation
	byte_string concatBuf;
	if (vEncryptedStrings.size() * minCipherLen > concatBuf.max_size()) {
		std::cout << "Problem with using a string here" << std::endl;
		return false;
	}

	for (auto cs : vEncryptedStrings) {
		concatBuf += cs.substr(0, minCipherLen);
	}

	// Decrypt the buffer using repeated-XOR technique with a key size equal to minCipherLen
	std::unique_ptr<byte[]> spWholeKey = std::unique_ptr<byte[]>(new byte[minCipherLen]);
	byte* pKey = spWholeKey.get();

	std::unique_ptr<char[]> pResult = 
		crypto_utils::decodeUsingFixedKeyLength(concatBuf.c_str(), concatBuf.length(), pKey, minCipherLen);


	//dbg_utils::displayBytes("Key bytes: ", pKey, minCipherLen);

	std::cout << std::endl << pResult.get();

	return true;
}

bool Challenges::Set3Ch21()
{
	RNG rng;

	static const size_t numRands = 10;
	static const uint32_t seed = getRandomNumber();

	rng.Initialize(seed);

	std::vector<uint32_t> vRandNums;
	vRandNums.reserve(numRands);
	for (size_t i = 0; i < numRands; ++i) {
		vRandNums.push_back(rng.ExtractU32());
	}

	uint32_t minVal = 0;
	uint32_t maxVal = UINT32_MAX;

	std::cout << std::endl << "Here is a list of random numbers." << std::endl;
	std::cout << "Values are between " << minVal << " and " << maxVal << std::endl << std::endl;

	for (auto val : vRandNums) {
		std::cout << val << std::endl;
	}

	return true;
}