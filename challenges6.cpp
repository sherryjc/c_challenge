#include "challenges.h"
#include "utils.h"
#include "backend.h"

using namespace io_utils;
using namespace crypto_utils;
using namespace math_utils;


bool Challenges::Set6Ch41()
{

	Backend::Oracle6* pOracle = Backend::Oracle6::Get(41);
	const byte_string plaintxt = reinterpret_cast<byte*>("555-1234-55"); 
	byte_string ciphertxt;
	pOracle->Encrypt(plaintxt, ciphertxt);

	std::cout << "Plaintext " << plaintxt.c_str() << " encrypts to " << ciphertxt.c_str() << std::endl;
	return true;
}