#pragma once
#include "windows.h"
#include <compressapi.h>

enum SecHdrIdx {
    SHI_SPACE,
    SHI_CODE,
    SHI_COM,
    SHI_COUT
};

typedef HMODULE(WINAPI* PFN_LOADLIBRARYA)(LPCSTR);
typedef LPVOID(WINAPI* PFN_VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PFN_CREATEDECOMPRESSOR)(DWORD, PCOMPRESS_ALLOCATION_ROUTINES, PDECOMPRESSOR_HANDLE);
typedef BOOL(WINAPI * PFN_DECOMPRESS)(DECOMPRESSOR_HANDLE, LPCVOID, SIZE_T, PVOID, SIZE_T, PSIZE_T);
typedef BOOL(WINAPI* PFN_VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);


void  MyZeroMem(void* lpDstAddress, int dwSize);
DWORD MyMemCmp(void* lpDstAddress, void* lpSrcAddress, int dwSize);
void  MyMemCopy(void* lpDstAddress, void* lpSrcAddress, int dwSize);
int   MyStrLen(const char* pSrc);

void Pascal2CStr(char* pDst, const char* pSrc, int nSize);
void CStr2Pascal(char* pDst, const char* pSrc, int nSize);
BOOL CmpPascalStrWithCStr(const char* pPascalStr, const char* pCStr, int nCStrSize);


HMODULE MyGetModuleBase(LPCSTR lpModuleName);
LPVOID  MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName);
void    StretchPE(LPVOID lpDst, LPVOID lpFileBuff);
void    RepairIatTable(LPVOID lpFileBuff);
void    RepairReloc(LPVOID lpFileBuff);

