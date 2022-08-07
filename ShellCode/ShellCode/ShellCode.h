#pragma once
#include "windows.h"

/*
ģ����Ϣ��{
  +0  //ǰһ����ĵ�ַ
  +4  //��һ����ĵ�ַ
  +18 //��ǰģ��Ļ�ַ hInstance
  +1C //ģ�����ڵ�
  +20 //SizeOfImage
  +24 //Rtl��ʽ��unicode�ַ�����������ģ���·��
      {
        +0 //�ַ���ʵ�ʳ���
        +2 //�ַ�����ռ�Ŀռ��С
        +4 //unicode�ַ����ĵ�ַ
      }
  +2C //Rtl��ʽ��unicode�ַ�����������ģ�������
      {
        +0 //�ַ���ʵ�ʳ���
        +2 //�ַ�����ռ�Ŀռ��С
        +4 //unicode�ַ����ĵ�ַ
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



DWORD MyMemCmp(void* lpDstAddress, void* lpSrcAddress, int dwSize) {
    DWORD dwRet = 0;
    __asm {
        cld;
        mov edi, lpDstAddress;
        mov esi, lpSrcAddress;
        mov ecx, dwSize;
        repz cmpsb;
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


void MyMemCopy(void* lpDstAddress, void* lpSrcAddress, int dwSize) {
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


int MyStrLen(const char* pSrc) {
    int nLen = 0;
    while (pSrc[nLen] != '\0') {
        nLen++;
    }
    return nLen;
}


void Pascal2CStr(char* pDst, const char* pSrc, int nSize) {
    int nIndex = 0;
    for (int i = 0; i < nSize; i += 2) {
        pDst[nIndex] = pSrc[i];
        nIndex++;
    }
}


void CStr2Pascal(char* pDst, const char* pSrc, int nSize) {
    int nIndex = 0;
    for (int i = 0; i < nSize; ++i) {
        pDst[nIndex] = pSrc[i];
        pDst[nIndex + 1] = '\0';
        nIndex += 2;
    }
}



