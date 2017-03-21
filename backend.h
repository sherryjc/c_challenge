#pragma once


#include <string>
#include <memory>
#include "utils.h"

namespace Backend {

	// Set 2, Challenge 11
	const std::string EncryptionOracle_2_11(const char* pInput, size_t len);

	// Set 2, Challenge 12
	std::unique_ptr< byte[] > EncryptionOracle_2_12(const byte* pInput, size_t len, size_t& outLen);

	// Set 2, Challenge 13
	byte_string EncryptionOracle_2_13(const std::string& emailAddr);
	bool Add_User_2_13(const byte_string& encryptedRec);

	// Set 2, Challenge 14
	std::unique_ptr< byte[] > EncryptionOracle_2_14(const byte* pInput, size_t len, size_t& outLen);

	// Set 2, Challenge 16
	std::unique_ptr< byte[] >  EncryptionOracle_2_16(const std::string& strInput, size_t& outLen);
	std::string DecryptionOracle_2_16(const byte* pInput, size_t len);

}
