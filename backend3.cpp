#include "backend.h"
#include <unordered_map>
#include <iostream>
#include "aes.h"
#include "utils.h"

using namespace crypto_utils;
using namespace io_utils;

//////////////////////////////////////////////////////////////////////////
//
// Back end functions (Oracles, etc.) for Set 3
//
//////////////////////////////////////////////////////////////////////////

// ------------------------ //
// Set 3 Challenge 17       //
// ------------------------ //

// Extern that is not part of the public namespace - we don't want to expose this one!
extern void GetSessionKey(size_t blockSzBits, byte*& pKey, size_t& keySz, bool bCreate = false);

static const std::string _inputs[] = {
	"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
	"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
	"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
	"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
	"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
	"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
	"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
	"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
	"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
	"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};
static const std::string _dbginputs[] = {
	"abcdefghijklmnop0123456789ABCDEF",
	"abcdefghijklmnop0123456789ABCDE",
	"abcdefghijklmnop0123456789ABCD"
};

void Backend::DumpAllOracle_3_17()
{
	for (auto str : _inputs) {
		size_t outCnt = 0;
		std::unique_ptr<byte[]> p = crypto_utils::base64ToBin(str.c_str(), str.length(), outCnt);
		dbg_utils::displayBytes(str.c_str(), p.get(), outCnt);
	}
}

void Backend::EncryptionOracle_3_17(byte_string& ciphertext, byte_string& iv)
{
	// Generate a random AES key and cache it for the session
	// Select one of the above input strings at random
	// Pad it to the AES block size
	// CBC encrypt it
	// Return ciphertext and initialization vector

	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz, true);
	aes.SetKey(pKey, keySz);

	size_t inputIndex = crypto_utils::getRandomNumber() % _countof(_inputs);

	//aes.SetInput(_inputs[inputIndex], true);
	aes.SetInput(_dbginputs[2], true);
	aes.SetMode(Aes::CBC);
	aes.SetInitializationVector(Aes::RANDOM);
	aes.Encrypt();
	aes.ResultStr(ciphertext);
	aes.InitializationVector(iv);
}

// Models server's consumption of an encrypted session token (cookie)
// Returning whether the padding is valid is the side-channel leakage
// that enables the caller to decrypt the ciphertext.

bool Backend::DecryptionOracle_3_17(const byte_string& ciphertext, const byte_string& iv)
{
	// Decrypt the ciphertext
	// Return true or false depending on whether the padding is valid
	static const size_t kBlockSzBits = 128;
	Aes aes(kBlockSzBits);
	byte* pKey = nullptr;
	size_t keySz = 0;
	GetSessionKey(kBlockSzBits, pKey, keySz, true);
	aes.SetKey(pKey, keySz);
	aes.SetMode(Aes::CBC);
	aes.SetInitializationVector(iv);
	aes.SetInput(ciphertext);
	aes.Decrypt();

	std::string plainText;
	aes.ResultStr(plainText);
	std::string plainTextStripped;
	bool bPaddingValid = crypto_utils::stripPKCS7Padding(plainText, plainTextStripped, aes.BlockSize());

	return bPaddingValid;
}
