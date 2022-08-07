#pragma once
#include <Windows.h>


DWORD MyMemCmp(LPVOID lpDstAddress, LPVOID lpSrcAddress, DWORD dwSize);
void MyMemCopy(LPVOID lpDstAddress, LPVOID lpSrcAddress, DWORD dwSize);

int MyStrLen(const char* pSrc);

void Pascal2CStr(char* pDst, const char* pSrc, int nSize);
void CStr2Pascal(char* pDst, const char* pSrc, int nSize);