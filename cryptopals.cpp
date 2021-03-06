// cryptopals.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "challenges.h"

int main(int argc, char* argv[])
{
	// printf("Called with %d arguments", argc);
	bool bRc = true;
	int testToRun = 0;
	int testArg = 0;
	if (argc > 1) {
		testToRun = atoi(argv[1]);
	}
	if (argc > 2) {
		testArg = atoi(argv[2]);
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
	case 16:
		bRc &= Challenges::Set2Ch16();
		break;
	case 17:
		bRc &= Challenges::Set3Ch17();
		break;
	case 18:
		bRc &= Challenges::Set3Ch18();
		break;
	case 19:
		bRc &= Challenges::Set3Ch19();
		break;
	case 20:
		bRc &= Challenges::Set3Ch20();
		break;
	case 21:
		bRc &= Challenges::Set3Ch21();
		break;
	case 22:
		bRc &= Challenges::Set3Ch22();
		break;
	case 25:
		bRc &= Challenges::Set4Ch25();
		break;
	case 26:
		bRc &= Challenges::Set4Ch26();
		break;
	case 27:
		bRc &= Challenges::Set4Ch27();
		break;
	case 28:
		bRc &= Challenges::Set4Ch28();
		break;
	case 29:
		bRc &= Challenges::Set4Ch29();
		break;
	case 33:
		bRc &= Challenges::Set5Ch33();
		break;
	case 34:
		bRc &= Challenges::Set5Ch34(testArg);
		break;
	case 36:
		bRc &= Challenges::Set5Ch36();
		break;
	case 39:
		bRc &= Challenges::Set5Ch39();
		break;
	case 40:
		bRc &= Challenges::Set5Ch40();
		break;
	case 41:
		bRc &= Challenges::Set6Ch41();
		break;
	case 0:
	default:
		bRc &= Challenges::Set6Ch41();
		break;
	}

	return bRc == true ? 0 : 1;
}


