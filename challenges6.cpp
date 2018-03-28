#include "challenges.h"
#include "utils.h"
#include "backend.h"

using namespace io_utils;
using namespace crypto_utils;
using namespace math_utils;


bool Challenges::Set6Ch41()
{

	Backend::Oracle6* pOracle = Backend::Oracle6::Get(41);
	const byte_string plaintxt = reinterpret_cast<byte*>("{SSN: 123-4567-89}"); 
	byte_string cipher;
	size_t totalCount = 0;
	std::vector<byte_string> vCipherTxts;

	while (true)
	{
		size_t cnt = 0;
		byte_string cipher;
		byte_string workStr = plaintxt.substr(totalCount);  // substr starting at count index

		bool bRet = pOracle->EncryptBlock(workStr, cipher, cnt);
		std::cout << "Plaintext " << workStr.c_str() << " encrypts to " << cipher.length() << " bytes" << std::endl;
		dbg_utils::displayHex(cipher);
		if (bRet == false || cnt == 0)
		{
			std::cout << "An error occurred, we are done" << std::endl;
			break;
		}
		vCipherTxts.emplace_back(cipher);
		totalCount += cnt;
		if (totalCount >= plaintxt.length())
		{
			std::cout << "We have reached the end" << std::endl;
			break;
		}
		std::cout << "We have more plaintext to encrypt" << std::endl;


	}

	std::cout << "Decrypting" << std::endl;
	byte_string fullDecryptedText;

	for (auto cipher : vCipherTxts)
	{
		byte_string text;
		bool bRet = pOracle->DecryptBlock(cipher, text);
		if (!bRet)
		{
			std::cout << "An error occurred while decrypting" << std::endl;
		}
		fullDecryptedText += text;

	}

	std::cout << std::endl << "Ciphertext decrypts to " << fullDecryptedText.c_str() << std::endl;

	return true;
}