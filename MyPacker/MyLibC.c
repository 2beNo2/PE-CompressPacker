#include "MyLibC.h"


DWORD MyMemCmp(LPVOID lpDstAddress, LPVOID lpSrcAddress, DWORD dwSize) {
	DWORD dwRet = 0;
	__asm {
		cld;
		mov edi, lpDstAddress;
		mov esi, lpSrcAddress;
		mov ecx, dwSize;
		repz cmpsb; // 相等时循环
		jnz NOT_EQUAL;
		mov eax, 0;
		jmp EXIT_FUN;
	NOT_EQUAL:
		sub edi, esi;
		mov eax, edi;
	EXIT_FUN:
		mov dwRet, eax
	}
	return dwRet;
}


void MyMemCopy(LPVOID lpDstAddress, LPVOID lpSrcAddress, DWORD dwSize) {
	__asm {
		cld;
		mov edi, lpDstAddress;
		mov esi, lpSrcAddress;
		mov eax, dwSize;
		xor edx, edx;
		mov ecx, 4;
		div ecx;
		mov ecx, eax;
		rep movsd;
		mov ecx, edx;
		rep movsb;
	}
}
