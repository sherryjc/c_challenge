/*
SHA1 tests by Philip Woolford <woolford.philip@gmail.com>
100% Public Domain
 */

#include "sha1.h"
#include "stdafx.h"

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
		const byte_string string = reinterpret_cast<byte*>("abc");
		const byte_string expect = reinterpret_cast<const byte *>("a9993e364706816aba3e25717850c26c9cd0d89d");
		byte result[21];
		byte hexresult[41];
		size_t offset;

		/* calculate hash */
		SHA1(result, string.c_str(), string.length());

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((reinterpret_cast<char*>(hexresult) + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec1", strncmp(reinterpret_cast<char*>(hexresult), reinterpret_cast<const char*>(expect.c_str()), 40) == SUCCESS);
	}

	/* Test Vector 2 */
	void testvec2(
		void
	)
	{
		const byte_string string = reinterpret_cast<byte *>("");
		const byte_string expect = reinterpret_cast<byte *>("da39a3ee5e6b4b0d3255bfef95601890afd80709");
		byte result[21];
		byte hexresult[41];
		size_t offset;

		/* calculate hash */
		SHA1(result, string.c_str(), string.length());

		/*format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((reinterpret_cast<char*>(hexresult) + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec2", strncmp(reinterpret_cast<char*>(hexresult), reinterpret_cast<const char*>(expect.c_str()), 40) == SUCCESS);
	}

	/* Test Vector 3 */
	void testvec3(
		void
	)
	{
		const byte_string string = reinterpret_cast<byte *>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
		const byte_string expect = reinterpret_cast<byte *>("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
		byte result[21];
		byte hexresult[41];
		size_t offset;

		/* calculate hash */
		SHA1(result, string.c_str(), string.length());

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((reinterpret_cast<char*>(hexresult) + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec3", strncmp(reinterpret_cast<char*>(hexresult), reinterpret_cast<const char*>(expect.c_str()), 40) == SUCCESS);
	}

	/* Test Vector 4 */
	void testvec4(
		void
	)
	{
		const byte_string string1 = reinterpret_cast<byte *>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghij");
		const byte_string string2 = reinterpret_cast<byte *>("klmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
		const byte_string expect = reinterpret_cast<byte *>("a49b2446a02c645bf419f995b67091253a04a259");
		byte result[21];
		byte hexresult[41];
		size_t offset;
		SHA1_CTX ctx;

		/* calculate hash */
		SHA1Init(&ctx);
		SHA1Update(&ctx, string1.c_str(), string1.length());
		SHA1Update(&ctx, string2.c_str(), string2.length());
		SHA1Final(result, &ctx);

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((reinterpret_cast<char*>(hexresult) + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec4", strncmp(reinterpret_cast<char*>(hexresult), reinterpret_cast<const char*>(expect.c_str()), 40) == SUCCESS);
	}

	/* Test Vector 5 */
	void testvec5(
		void
	)
	{
		const byte_string expect = reinterpret_cast<byte *>("34aa973cd4c4daa4f61eeb2bdbad27316534016f");
		byte result[21];
		byte hexresult[41];
		size_t offset;

		/* generate string */
		byte_string str;
		constexpr size_t kArraySz = 1000000;
		str.reserve(kArraySz);
		for (size_t idx = 0; idx < kArraySz; idx++) {
			str += 'a';
		}

		/* calculate hash */
		SHA1(result, str.c_str(), str.length());

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((reinterpret_cast<char*>(hexresult) + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec5", strncmp(reinterpret_cast<char*>(hexresult), reinterpret_cast<const char*>(expect.c_str()), 40) == SUCCESS);
	}

	/* Test Vector 6 */
	void testvec6(
		void
	)
	{
		const byte_string string = reinterpret_cast<byte *>("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno");
		const byte_string expect = reinterpret_cast<byte *>("7789f0c9ef7bfc40d93311143dfbe69e2017f592");
		byte result[21];
		byte hexresult[41];
		int iterator;
		size_t offset;
		SHA1_CTX ctx;

		/* calculate hash */
		SHA1Init(&ctx);
		for (iterator = 0; iterator < 16777216; iterator++) {
			SHA1Update(&ctx, string.c_str(), string.length());
		}
		SHA1Final(result, &ctx);

		/* format the hash for comparison */
		for (offset = 0; offset < 20; offset++) {
			sprintf((reinterpret_cast<char*>(hexresult) + (2 * offset)), "%02x", result[offset] & 0xff);
		}

		CU_ASSERT("testvec5", strncmp(reinterpret_cast<char*>(hexresult), reinterpret_cast<const char*>(expect.c_str()), 40) == SUCCESS);
	}

	void RunTest(const std::string& name, void func())
	{
		std::cout << "Running test " << name << std::endl;
		func();
	}

}

void SHA1_Test_RunAll()
{
	using namespace SHA1_Test;

	RunTest("Testvec1", testvec1);
	RunTest("Testvec2", testvec2);
	RunTest("Testvec3", testvec3);
	RunTest("Testvec4", testvec4);
	RunTest("Testvec5", testvec5);
	RunTest("Testvec6", testvec6);
}
