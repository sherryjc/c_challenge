/*
SHA1 tests by Philip Woolford <woolford.philip@gmail.com>
100% Public Domain
 */

#include "sha1.h"
#include "stdafx.h"
#include "sha1_test.h"

#define SUCCESS 0

namespace SHA1_Test 
{

	void CU_ASSERT(const std::string& name, bool bResult)
	{
		if (!bResult)
		{
			std::cout << "Test " << name << " FAILED" << std::endl;
		}
	}

	/* Test Vector 1 */
	void testvec1(
		void
	)
	{
		char const string[] = "abc";
		char const expect[] = "a9993e364706816aba3e25717850c26c9cd0d89d";
		char result[21];
		char hexresult[41];
		size_t offset;

		/* calculate hash */
		SHA1(result, string, strlen(string));

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec1", strncmp(hexresult, expect, 40) == SUCCESS);
	}

	/* Test Vector 2 */
	void testvec2(
		void
	)
	{
		char const string[] = "";
		char const expect[] = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
		char result[21];
		char hexresult[41];
		size_t offset;

		/* calculate hash */
		SHA1(result, string, strlen(string));

		/*format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec2", strncmp(hexresult, expect, 40) == SUCCESS);
	}

	/* Test Vector 3 */
	void testvec3(
		void
	)
	{
		char const string[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		char const expect[] = "84983e441c3bd26ebaae4aa1f95129e5e54670f1";
		char result[21];
		char hexresult[41];
		size_t offset;

		/* calculate hash */
		SHA1(result, string, strlen(string));

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec3", strncmp(hexresult, expect, 40) == SUCCESS);
	}

	/* Test Vector 4 */
	void testvec4(
		void
	)
	{
		char const string1[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghij";
		char const string2[] = "klmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		char const expect[] = "a49b2446a02c645bf419f995b67091253a04a259";
		unsigned char result[21];
		char hexresult[41];
		size_t offset;
		SHA1_CTX ctx;

		/* calculate hash */
		SHA1Init(&ctx);
		SHA1Update(&ctx, (unsigned char const *)string1, strlen(string1));
		SHA1Update(&ctx, (unsigned char const *)string2, strlen(string2));
		SHA1Final(result, &ctx);

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec4", strncmp(hexresult, expect, 40) == SUCCESS);
	}

	/* Test Vector 5 */
	void testvec5(
		void
	)
	{
		char string[1000001];
		char const expect[] = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";
		char result[21];
		char hexresult[41];
		int iterator;
		size_t offset;

		/* generate string */
		for (iterator = 0; iterator < 1000000; iterator++) {
			string[iterator] = 'a';
		}
		string[1000000] = '\0';

		/* calculate hash */
		SHA1(result, string, strlen(string));

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec5", strncmp(hexresult, expect, 40) == SUCCESS);
	}

	/* Test Vector 6 */
	void testvec6(
		void
	)
	{
		char const string[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
		char const expect[] = "7789f0c9ef7bfc40d93311143dfbe69e2017f592";
		unsigned char result[21];
		char hexresult[41];
		int iterator;
		size_t offset;
		SHA1_CTX ctx;

		/* calculate hash */
		SHA1Init(&ctx);
		for (iterator = 0; iterator < 16777216; iterator++) {
			SHA1Update(&ctx, (unsigned char const *)string, strlen(string));
		}
		SHA1Final(result, &ctx);

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((hexresult + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec6", strncmp(hexresult, expect, 40) == SUCCESS);
	}

	void RunTest(const std::string& name, void func())
	{
		std::cout << "Running test " << name << std::endl;
		func();
	}

}

void SHA1_Test::RunAll()
{
	using namespace SHA1_Test;

	RunTest("Testvec1", testvec1);
	RunTest("Testvec2", testvec2);
	RunTest("Testvec3", testvec3);
	RunTest("Testvec4", testvec4);
	RunTest("Testvec5", testvec5);
	RunTest("Testvec6", testvec6);
}
