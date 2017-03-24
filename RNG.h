#pragma once

// Random Number Generator

// Copied from https://en.wikipedia.org/wiki/Mersenne_Twister

#include <stdint.h>

class RNG {

public:
	RNG() {};
	~RNG() {};
	RNG(const RNG& other) = delete;
	RNG(const RNG&& other) = delete;
	RNG& operator=(const RNG& other) = delete;
	RNG& operator=(const RNG&& other) = delete;

	void Initialize(const uint32_t  seed);
	uint32_t ExtractU32();


};
