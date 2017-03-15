

#include "backend.h"
#include <unordered_map>
#include <iostream>
#include "aes.h"
#include "utils.h"

using namespace crypto_utils;



// ------------------------ //
// Set 2 Challenge 11      //
// ------------------------ //

const std::string Backend::EncryptionOracle_2_11(const char* pInput, size_t len)
{
	// 1. Generate a random key (of the same length as the block size)
	// 2. Append bytes before and after the plain text, numbers of bytes chosen randomly
	// 3. Encrypt, choosing ECB or CBC randomly
	// 4. Return the encrypted string (the members of which are actually bytes)

	Aes aes(128);
	aes.SetKey(aes.BlockSize());

	aes.ModifyInput1(pInput, len);
	aes.InitOutput();  // default to size of input

	aes.SetMode(getRandomBool() ? Aes::CBC : Aes::ECB);
	aes.SetInitializationVector(aes.Mode() == Aes::CBC ? Aes::RANDOM : Aes::ALL_ZEROES);
	aes.Encrypt();
	size_t outLen = 0;
	const byte* pResult = aes.Result(outLen);
	return reinterpret_cast<const char*>(pResult);
}

// ------------------------ //
// Set 2 Challenge 13       //
// ------------------------ //


std::unordered_map<std::string, std::string> s_UserDb;

static void DumpUserDb(bool b)
{
	std::cout << std::endl << "Input string was ";
	if (b) {
		std::cout << "VALID" << std::endl;
	}
	else {
		std::cout << "INVALID" << std::endl;
	}

	std::cout << std::endl << "{" << std::endl;
	bool bFirst = true;
	for (auto& x : s_UserDb) {
		if (!bFirst) {
			std::cout << ',' << std::endl;
		}
		bFirst = false;
		std::cout << "\t" << x.first << ":\t\t\'" << x.second << "\'";
	}
	std::cout << std::endl << "}" << std::endl;
}

static bool ValidKeyChar(char c)
{
	return (isalpha(c) || isdigit(c));
}

static bool ValidValChar(char c)
{
	return (isalpha(c) || isdigit(c) || c == '@' || c == '.');
}

static bool ValidEmailAddr(const std::string& addr)
{
	// Just enforces n@m, i.e. at least one char + @ + at least one char
	bool bGotBefore = false;
	bool bGotAt = false;
	bool bGotAfter = false;

	for (auto c : addr) {
		if (!ValidValChar(c)) {
			return false;
		}
		if (c == '@') {
			// There can only be one '@'
			if (bGotAt) {
				return false;
			}
			bGotAt = true;
		}
		else {
			// Valid, not @
			if (!bGotAt) {
				bGotBefore = true;
			}
			else {
				bGotAfter = true;
			}
		}
	}
	return bGotBefore && bGotAt && bGotAfter;
}

static bool ValidUid(const std::string& addr)
{
	for (auto c : addr) {
		if (!isdigit(c)) {
			return false;
		}
	}
	return true;
}

static bool ParseDbRec(const std::string& str)
{
	// states:
	//  0  looking for key start
	//  1  in key
	//  2  looking for value start
	//  3  in value
	//  Symbol 'V': valid key or value character
	//  x: invalid transition

	//      V    =   &
	//  0:  1    x   x
	//  1:  1    2   x
	//  2:  3    x   x
	//  3:  3    x   0


	int state = 0;
	static const size_t kMAXLEN = 256;
	size_t inputLen = str.length();
	if (inputLen > kMAXLEN) {
		return false;
	}
	size_t pos = 0;
	const char *pC = str.c_str();
	std::string currKey;
	std::string currVal;

	while (pos < inputLen) {
		char c = *pC++;
		pos++;

		switch (state)
		{
		case 0:
			if (ValidKeyChar(c)) {
				currKey += c;
				state = 1;
			}
			else {
				return false;
			}
			break;
		case 1:
			if (ValidKeyChar(c)) {
				currKey += c;
			}
			else if (c == '=') {
				state = 2;
			}
			else {
				return false;
			}
			break;
		case 2:
			if (ValidValChar(c)) {
				currVal += c;
				state = 3;
			}
			else if (c == '=') {
				state = 2;
			}
			else {
				return false;
			}
			break;
		case 3:
			if (ValidValChar(c)) {
				currVal += c;
			}
			else if (c == '&') {
				std::pair<std::string, std::string>entry(currKey, currVal);
				s_UserDb.insert(entry);
				currKey.clear();
				currVal.clear();
				state = 0;
			}
			else {
				return false;
			}
			break;
		default:
			return false;
		}

	}

	if (state == 3) {
		std::pair<std::string, std::string>entry(currKey, currVal);
		s_UserDb.insert(entry);
		state = 0;
	}

	return state == 0;

}

static std::string EncodeProfile(const std::string& emailAddr, const std::string& strUid, const std::string& strRole)
{
	std::string str;
	if (!ValidEmailAddr(emailAddr)) {
		return str;
	}
	if (!ValidUid(strUid)) {
		return str;
	}

	str = "email=";
	str += emailAddr;

	str += "&uid=";
	str += strUid;
	str += "&role=";
	str += strRole;

	return str;
}


std::string Backend::Oracle_2_13(const std::string& emailAddr)
{
	// Given an "email address", returns the encrypted encoding string for the user entry
	std::string uid("100");
	std::string user("user");
	std::string encodedProfile = EncodeProfile(emailAddr, uid, user);
	if (encodedProfile.length() == 0) {
		return "";
	}
	Aes aes(128);
	std::string resultStr;
	return resultStr;
}

void Backend::Add_User_2_13(const std::string& encryptedRec)
{
	// Decrypt the input
	// Parse the plaintext and add a user to the Db if valid
	// Print out the change to the db

}
