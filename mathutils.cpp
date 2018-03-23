
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

static int _gcd(int a, int b)   // assumes a >= b already checked
{
	if (b == 0) return a;

	return(_gcd(b, a%b));
}

// Publicly-exposed variant adjusts so that a >= b
int math_utils::gcd(int a, int b)
{
	// Reverse the roles if b > a
	if (b > a) return _gcd(b, a);

	return _gcd(a, b);
}

static void inline _update(int& curr, int& last, int q, int tmp)
{
	tmp = last;
	last = curr;
	curr = tmp - q*curr;
}

static int _extended_gcd(int a, int b, int& lambda, int& mu)
{
	/*
	 * Some pseudocode to help visualize this
	r[-1] = a;
	r[0] = b;
	lm[-1] = 1;
	lm[0] = 0;
	mu[-1] = 0;
	mu[0] = 1;
	i = 0;
	while (!done)
	{
		q[i+1] = r[i-1]/r[i];
		lm[i+1] = lm[i-1] - q[i+1]*lm[i];
		mu[i+1] = mu[i-1] - q[i+1]*mu[i];
		r[i+1] =  r[i-1] -  q[i+1]*r[i];
		// r[i+1] = a*lm[i+1] + b*lm[i+1]  true at each step; not actually computed
		if (r[i+1] == 0)
		{
		   lambda = lm[i]
		   mu = mu[i]
		   return gcd = r[i]
		}
		++i;
	}

	*/

	int tmp = 0;
	int q = 0;
	int r_last = a;
	int r_curr = b;
	int lm_last = 1;
	int lm_curr = 0;
	int mu_last = 0;
	int mu_curr = 1;

	while (true)
	{
		q = r_last / r_curr;
		_update(r_curr, r_last, q, tmp);
		if (r_curr == 0) break;
		_update(lm_curr, lm_last, q, tmp);
		_update(mu_curr, mu_last, q, tmp);
	}

	lambda = lm_curr;
	mu = mu_curr;
	return r_last;  // == gcd(a,b)

}

int math_utils::extended_gcd(int a, int b, int& lambda, int& mu)
{
	// Reverse the roles if b > a
	if (b > a) return _extended_gcd(b, a, lambda, mu);

	return _extended_gcd(a, b, lambda, mu);
}

bool math_utils::invmod(int a, int m, int& a_inv)
{
	// This is a simplification of the extended_gcd function.
	// We want a_inv = inverse of a.
	// If and only if the inverse exists, then a is co-prime to m, so gcd(m, a) = 1, and
	//        lamda*m + mu*a = 1
	//   or   mu*a = 1 - lambda*m 
	//   or   mu*a = 1 mod m
	// So the mu from the extended_gcd is the inverse of 'a' mod m. 
	// Note we don't need the lambda from the extended_gcd, so it's not computed.

	if (a > m) a = a % m;

	int tmp = 0;
	int q = 0;
	int r_last = m;
	int r_curr = a;
	int mu_last = 0;
	int mu_curr = 1;

	while (true)
	{
		q = r_last / r_curr;
		_update(r_curr, r_last, q, tmp);
		if (r_curr == 0) break;
		_update(mu_curr, mu_last, q, tmp);
	}

	if (r_last > 1) return false;   // a is not invertible (mod m)

	if (mu_curr < 0)
	{
		mu_curr += m;
	}
	a_inv = mu_curr;
	return true;
}

bool math_utils::checkInvMod(int a, int a_inv, int m)
{
	return ((a * a_inv) % m == 1);
}


bool math_utils::byteBufToULL(const byte* pBytes, size_t nBytes, unsigned long long& ull)
{
	// We can only handle 16 hex bytes.
	// From limits.h
	// #define ULLONG_MAX    0xffffffffffffffffui64       // maximum unsigned long long int value
	return false;
}
