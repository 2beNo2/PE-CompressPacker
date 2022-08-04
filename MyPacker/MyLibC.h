#pragma once
#include <Windows.h>

DWORD MyMemCmp(LPVOID lpDstAddress, LPVOID lpSrcAddress, DWORD dwSize);
void MyMemCopy(LPVOID lpDstAddress, LPVOID lpSrcAddress, DWORD dwSize);
