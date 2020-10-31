#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Helper.h"
#include <iostream>
#include <Windows.h>
int main() {
	uHOST tHOST;
	tHOST.BasicHostInfos();
	tHOST.BasicIPInfos();
}