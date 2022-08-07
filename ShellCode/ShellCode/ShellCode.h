#pragma once
#include "windows.h"

/*
模块信息表{
  +0  //前一个表的地址
  +4  //后一个表的地址
  +18 //当前模块的基址 hInstance
  +1C //模块的入口点
  +20 //SizeOfImage
  +24 //Rtl格式的unicode字符串，保存了模块的路径
      {
        +0 //字符串实际长度
        +2 //字符串所占的空间大小
        +4 //unicode字符串的地址
      }
  +2C //Rtl格式的unicode字符串，保存了模块的名称
      {
        +0 //字符串实际长度
        +2 //字符串所占的空间大小
        +4 //unicode字符串的地址
      }
}
*/
struct MY_LIST_ENTRY {
    struct MY_LIST_ENTRY* Flink;  //0x0
    struct MY_LIST_ENTRY* Blink;  //0x4
    int n1;    //0x8
    int n2;    //0xC
    int n3;    //0x10
    int n4;    //0x14
    HMODULE hInstance;      //0x18
    void* pEntryPoint;      //0x1C
    int nSizeOfImage;       //0x20

    short sLengthOfPath;    //0x24
    short sSizeOfPath;      //0x26
    int* pUnicodePathName;  //0x28

    short sLengthOfFile;    //0x2C
    short sSizeOfFile;      //0x2E
    int* pUnicodeFileName;  //0x30
};

typedef HMODULE(WINAPI* PFN_LOADLIBRARYA)(LPCSTR);

void  MyZeroMem(void* lpDstAddress, int dwSize);
DWORD MyMemCmp(void* lpDstAddress, void* lpSrcAddress, int dwSize);
void  MyMemCopy(void* lpDstAddress, void* lpSrcAddress, int dwSize);
int   MyStrLen(const char* pSrc);

void Pascal2CStr(char* pDst, const char* pSrc, int nSize);
void CStr2Pascal(char* pDst, const char* pSrc, int nSize);
BOOL CmpPascalStrWithCStr(const char* pPascalStr, const char* pCStr, int nCStrSize);


HMODULE MyGetModuleBase(LPCSTR lpModuleName);
LPVOID MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName);