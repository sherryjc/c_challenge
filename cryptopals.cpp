// cryptopals.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "utils.h"

static const char* pHexFile = "./data/set1/challenge1/input.hex";
static const char* pOutBase64 = "./data/set1/challenge1/outputB64.hex";
static const char* pHexFile2 = "./data/set1/challenge1/roundtrip.hex";

int _tmain(int argc, _TCHAR* argv[])
{
	//_tprintf(L"Called with %d arguments", argc);

	bool bRc = crypto_utils::convHexToBase64(pHexFile, pOutBase64);
	bRc = crypto_utils::convBase64ToHex(pOutBase64, pHexFile2);
	return 0;
}


