
#include "utils.h"
#include "n.h"

// Global "bignum" functions moved here from n.h

N operator + (const N& lhs, const N& rhs)
{
	N n = lhs;
	n += rhs;
	return n;
}

N operator - (const N& lhs, const N& rhs)
{
	N n = lhs;
	n -= rhs;
	return n;
}

N operator / (const N& lhs, const N& rhs)
{
	N n = lhs;
	n /= rhs;
	return n;
}

N operator % (const N& lhs, const N& rhs)
{
	N n = lhs;
	n %= rhs;
	return n;
}

N operator | (const N& lhs, const N& rhs)
{
	N n = lhs;
	n |= rhs;
	return n;
}

N operator & (const N& lhs, const N& rhs)
{
	N n = lhs;
	n &= rhs;
	return n;
}

N operator ^ (const N& lhs, const N& rhs)
{
	N n = lhs;
	n ^= rhs;
	return n;
}

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

// Large-number variants

// result = a mod m
void math_utils::mod(const N& a, const N& m, N& result)
{
	result = a % m;
}

// This version based on the 3p "N" (n.h) will never finish if the arguments get at all large.
// result = (b ^ e) mod m
void math_utils::modexp(const N& b, const N& e, const N& m, N& result)
{
	// Iterative approach
	N zero("0");
	if (e < zero || m <= zero) return;

	result = "1";	// will contain the answer
	N ee("0");		// current effective exponent as we accumulate powers of b (mod m)

	while (true)
	{
		++ee;
		result *= b;
		result %= m;
		if (ee >= e) break;
	}
}