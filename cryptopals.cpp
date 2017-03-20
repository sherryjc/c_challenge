// cryptopals.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "challenges.h"

int main(int argc, char* argv[])
{
	// printf("Called with %d arguments", argc);
	bool bRc = true;
	int testToRun = 0;
	if (argc > 1) {
		testToRun = atoi(argv[1]);
	}
	switch (testToRun) {
	case 1:
		bRc &= Challenges::Set1Ch1();
		break;
	case 2:
		bRc &= Challenges::Set1Ch2();
		break;
	case 3:
		bRc &= Challenges::Set1Ch3();
		break;
	case 4:
		bRc &= Challenges::Set1Ch4();
		break;
	case 5:
		bRc &= Challenges::Set1Ch5();
		break;
	case 6:
		bRc &= Challenges::Set1Ch6();
		break;
	case 7:
		bRc &= Challenges::Set1Ch7();
		break;
	case 8:
		bRc &= Challenges::Set1Ch8();
		break;
	case 10:
		bRc &= Challenges::Set2Ch10();
		break;
	case 11:
		bRc &= Challenges::Set2Ch11();
		break;
	case 12:
		bRc &= Challenges::Set2Ch12();
		break;
	case 13:
		bRc &= Challenges::Set2Ch13();
		break;
	case 14:
		bRc &= Challenges::Set2Ch14();
		break;
	case 15:
		bRc &= Challenges::Set2Ch15();
		break;
	case 0:
	default:
		bRc &= Challenges::Set2Ch15();
		break;
	}

	return bRc == true ? 0 : 1;
}


