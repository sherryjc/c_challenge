// cryptopals.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "challenges.h"

int main(int argc, char* argv[])
{
	// printf("Called with %d arguments", argc);
	bool bRc = true;

	bRc &= Challenges::Set1Ch1();
	//bRc &= Challenges::Set1Ch2();
	//bRc &= Challenges::Set1Ch3();
	//bRc &= Challenges::Set1Ch4();
	//bRc &= Challenges::Set1Ch5();
	//bRc &= Challenges::Set1Ch6x();

	return bRc == true ? 0 : 1;
}


