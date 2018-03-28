#include "challenges.h"
#include "utils.h"
#include "backend.h"

using namespace io_utils;
using namespace crypto_utils;
using namespace math_utils;


static bool _TextEncryptMultipleBlocks()
{

	Backend::Oracle6* pOracle = Backend::Oracle6::Get(41);
	const byte_string plaintxt = reinterpret_cast<byte*>("{SSN: 123-4567-89}"); 
	size_t totalCount = 0;
	std::vector<byte_string> vCipherTxts;

	// This tests encrypting multiple blocks. I don't know if RSA is actually ever used that way though.
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

static void _DisplayDecryption(bool bStatus, const byte_string& txt)
{
	if (!bStatus)
	{
		std::cout << "Decryption failed" << std::endl;
	}
	else
	{
		std::cout << "Decrypted text " << txt.c_str() << std::endl;
	}

}

void _bad(const std::string& s)
{
	std::cout << s << " failed" << std::endl;
}

bool Challenges::Set6Ch41()
{
	Backend::Oracle6* pOracle = Backend::Oracle6::Get(41);
	const byte_string plaintxt = reinterpret_cast<byte*>("{ time: 1356304276, SSN: 123-4567-89 }");
	byte_string cipher;
	size_t cnt = 0;
	bool bRet = pOracle->EncryptBlock(plaintxt, cipher, cnt);
	if (!bRet) { _bad("Encrypt"); }

	byte_string recoveredText;
	bRet = pOracle->DecryptBlock(cipher, recoveredText);
	_DisplayDecryption(bRet, recoveredText);

	// Try to query with the same ciphertext again, should fail
	byte_string recoveredText2;
	bRet = pOracle->DecryptBlock(cipher, recoveredText2);
	std::cout << "(Expect fail) ";
	_DisplayDecryption(bRet, recoveredText2);

	//  c = m**e % n
	//  m is the message we want to recover
	//  Compute c2 = ((s**e % n) * c) % n
	//  Because these messages are in an Abelian group (integers modulo n), (ab)**n = (a**n)(b**n)
	//  c2 = ((s**e % n) * (m**e % n) % n
	//     = (sm)**e % n
	//  Submit c2 to the decryption Oracle, get back (sm) = p2
	//  Then m = invmod(s, n)* p2


	BN_CTX* pCtx = BN_CTX_new();

	BIGNUM* E = nullptr;
	BIGNUM* N = nullptr;
	pOracle->PublicKey(&E, &N);

	BIGNUM* c = BN_new();
	BIGNUM* pRet = BN_bin2bn(cipher.c_str(), (int)cipher.length(), c);
	if (!pRet || !c) _bad("bin2bn");

	BIGNUM* s = BN_new();
	BN_set_word(s, 7);  // random number > 1 mod N

	// se = s**E mod N
	BIGNUM* se = BN_new();
	int rc = BN_mod_exp(se, s, E, N, pCtx);
	if (0 == rc) _bad("mod_exp");
	//dbg_utils::dumpBN("se: ", se);

	// c2 = (se * c) mod N
	BIGNUM* c2 = BN_new();
	rc = BN_mod_mul(c2, se, c, N, pCtx);
	if (0 == rc) _bad("mod_mul");

	// convert c2 to a string to pass to the Oracle
	byte_string c2_str;
	size_t nBytes = BN_num_bytes(c2);
	std::unique_ptr<byte[]> pC2(new byte[nBytes + 1]);
	byte* p = pC2.get();
	rc = BN_bn2bin(c2, p);
	if (0 == rc) _bad("bn2bin");
	io_utils::FillByteString(c2_str, p, nBytes);

	byte_string sm_str;
	bRet = pOracle->DecryptBlock(c2_str, sm_str);
	if (bRet) {
		std::cout << "Decryption of c2 ok: " << std::endl;
	}
	else {
		std::cout << "Decryption of c2 FAILED " << std::endl;
	}

	BIGNUM* sm = BN_new();
	pRet = BN_bin2bn(sm_str.c_str(), (int)sm_str.length(), sm);
	if (!pRet || !sm) _bad("bin2bn");
	//dbg_utils::dumpBN("sm: ", sm);

	// sinv = inv(s) mod N
	BIGNUM* sinv = BN_new();
	pRet = BN_mod_inverse(sinv, s, N, pCtx);
	if (!pRet) _bad("mod_inverse");

	// m = (inv(s) * sm) mod N
	BIGNUM* new_m = BN_new();
	rc = BN_mod_mul(new_m, sinv, sm, N, pCtx);
	if (0 == rc) _bad("mod_mul");

	byte_string new_m_str;
	nBytes = BN_num_bytes(new_m);
	std::unique_ptr<byte[]> pM(new byte[nBytes + 1]);
	p = pM.get();
	rc = BN_bn2bin(new_m, p);
	if (0 == rc) _bad("bn2bin");
	io_utils::FillByteString(new_m_str, p, nBytes);

	std::cout << "And our recovered text is ... " << std::endl;
	dbg_utils::displayHex(new_m_str);
	std::cout << std::endl;
	_DisplayDecryption(true, new_m_str);


	// I really need to write a wrapper function to do this
	BN_free(E);
	BN_free(N);
	BN_free(c);
	BN_free(s);
	BN_free(se);
	BN_free(c2);
	BN_free(sinv);
	BN_free(sm);
	BN_free(new_m);
	BN_CTX_free(pCtx);

	return true;
}