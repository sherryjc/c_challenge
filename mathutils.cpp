
#include "utils.h"
#include <limits.h>


// b^e mod m    (b=base, e=exponent, m=modulus)
//
// Relies on the fact that:
// c mod m = (a*b)mod m
//         = [(a mod m)*(b mod m)] mod m

int math_utils::modexp(int b, int e, int m)
{
	if (e < 0 || m <= 0) return -1;

	int c = 1;		// will contain the answer
	int ee = 0;		// current effective exponent as we accumulate powers of b (mod m)

	while (true)
	{
		++ee;
		c = (b*c) % m;
		if (ee >= e) break;
	}
	return c;
}


bool math_utils::byteBufToULL(const byte* pBytes, size_t nBytes, unsigned long long& ull)
{
	// We can only handle 16 hex bytes.
	// From limits.h
	// #define ULLONG_MAX    0xffffffffffffffffui64       // maximum unsigned long long int value
	return false;
}
