// ShellCode.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "ShellCode.h"


/*
ShellCode:
    -打开随机基址选项
    -修改为release
    -修改入口函数
    -关闭GS选项
    -关闭优化选项
    -字符串改用字节数组
    -API动态获取
*/
void Entry() { 
    // dll
    char szUser32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' }; 
    char szKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    char szCabinet[] = { 'C', 'a', 'b', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', '\0' };

    // api
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    char szVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    char szCreateDecompressor[] = { 'C', 'r', 'e', 'a', 't', 'e', 'D', 'e', 'c', 'o', 'm', 'p', 'r', 'e', 's', 's', 'o', 'r', '\0' };
    char szDecompress[] = { 'D', 'e', 'c', 'o', 'm', 'p', 'r', 'e', 's', 's', '\0' };

    HMODULE hKernel32 = MyGetModuleBase(szKernel32);
    HMODULE hUser32 = MyGetModuleBase(szUser32);
    HMODULE hCabinet = MyGetModuleBase(szCabinet);
    PFN_LOADLIBRARYA  pfnLoadLibraryA = (PFN_LOADLIBRARYA)MyGetProcAddress(hKernel32, szLoadLibraryA);
    PFN_VIRTUALALLOC pfnVirtualAlloc = (PFN_VIRTUALALLOC)MyGetProcAddress(hKernel32, szVirtualAlloc);
    PFN_CREATEDECOMPRESSOR pfnCreateDecompressor = (PFN_CREATEDECOMPRESSOR)MyGetProcAddress(hCabinet, szCreateDecompressor);
    PFN_DECOMPRESS pfnDecompress = (PFN_DECOMPRESS)MyGetProcAddress(hCabinet, szDecompress);
    
    // 当前程序的PE格式解析
    HMODULE hMain = MyGetModuleBase(NULL);
    PIMAGE_DOS_HEADER pPackerDosHeader = (PIMAGE_DOS_HEADER)hMain;
    PIMAGE_NT_HEADERS pPackerNtHeader = (PIMAGE_NT_HEADERS)((char*)pPackerDosHeader + pPackerDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pPackerFileHeader = (PIMAGE_FILE_HEADER)(&pPackerNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pPackerOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pPackerNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pPackerSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pPackerOptionHeader + pPackerFileHeader->SizeOfOptionalHeader);

    // 解压数据
    DWORD dwComDataSize = pPackerSectionHeader[SHI_COM].PointerToLinenumbers; // 压缩数据的大小
    PBYTE pComDataBuff = (PBYTE)((char*)pPackerDosHeader + pPackerSectionHeader[SHI_COM].VirtualAddress); // 压缩数据的内存地址
    DWORD dwDeComDataSize = pPackerSectionHeader[SHI_COM].PointerToRelocations; // 解压后数据的大小
    LPVOID lpDecomDataBuff = pfnVirtualAlloc(NULL, dwDeComDataSize, MEM_COMMIT, PAGE_READWRITE); //  解压后数据的内存地址
    
    DECOMPRESSOR_HANDLE hDeCompressor;
    BOOL bSuccess = pfnCreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, NULL, &hDeCompressor);
    if (!bSuccess) {
        return;
    }

    DWORD dwDecompressedDataSize = 0;
    bSuccess = pfnDecompress(
                hDeCompressor,              //  Compressor Handle
                pComDataBuff,               //  Compressed data
                dwComDataSize,              //  Compressed data size
                lpDecomDataBuff,            //  Decompressed buffer
                dwDeComDataSize,            //  Decompressed buffer size
                &dwDecompressedDataSize);   //  Decompressed data size
    if (!bSuccess) {
        return;
    }

    // 拉伸PE
    StretchPE(pPackerDosHeader, lpDecomDataBuff);

    // 修复IAT
    RepairIatTable(pPackerDosHeader);

    // Reloc
    RepairReloc(pPackerDosHeader);

    // 跳到入口点
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpDecomDataBuff;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    DWORD dwEntryPoint = (DWORD)hMain + pOptionHeader->AddressOfEntryPoint;
    __asm jmp dwEntryPoint;
}


void RepairReloc(LPVOID lpFileBuff) {
    // PE格式解析
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuff;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    // 获取重定位表
    if (pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == NULL) {
        return;
    }
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((char*)pDosHeader +
                                pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD dwRelocSize = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    
    // 获取修正值
    DWORD dwRelocValue = (DWORD)pDosHeader - pOptionHeader->ImageBase;
    
    // 遍历重定位表
    DWORD dwReserve = 0;
    while (dwReserve != dwRelocSize){
        DWORD dwPageRva = pReloc->VirtualAddress;
        DWORD dwSizeOfBlock = pReloc->SizeOfBlock;

        WORD* pItem = (WORD*)((char*)pReloc + 8);
        DWORD dwItemCount = (pReloc->SizeOfBlock - 8) / 2;
        for (int i = 0; i < dwItemCount; ++i) {
            if (pItem[i] > 0x3000) {
                char* pTmp = (char*)pDosHeader + dwPageRva + (pItem[i] & 0xfff);
                *(DWORD*)pTmp = *(DWORD*)pTmp + dwRelocValue;
            }
        }

        dwReserve += dwSizeOfBlock;
    }
}


void RepairIatTable(LPVOID lpFileBuff) {
    // PE格式解析
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuff;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    // 获取导入表
    DWORD dwImportRva = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (dwImportRva == 0)
        return;

    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pDosHeader + dwImportRva);
    IMAGE_IMPORT_DESCRIPTOR ZeroImport;
    MyZeroMem(&ZeroImport, sizeof(ZeroImport));

    while (MyMemCmp(pImport, &ZeroImport, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0){
        // 判断是否为有效导入表项
        PIMAGE_THUNK_DATA32 pIat = (PIMAGE_THUNK_DATA32)((char*)pDosHeader + pImport->FirstThunk);
        if (pIat->u1.AddressOfData == NULL) {
            pImport++;
            continue;
        }

        // 判断是使用INT还是IAT
        DWORD dwThunkDataRva = pImport->OriginalFirstThunk;
        if (dwThunkDataRva == NULL) {
            dwThunkDataRva = pImport->FirstThunk;
        }
        PIMAGE_THUNK_DATA32 pThunkData = (PIMAGE_THUNK_DATA32)((char*)pDosHeader + dwThunkDataRva);

        // 获取dll 模块基址
        char* pDllName = (char*)pDosHeader + pImport->Name;
        HMODULE hModule = MyGetModuleBase(pDllName);

        // 遍历INT/IAT
        while (pThunkData->u1.AddressOfData != NULL) {
            // 判断是名称还是序号
            DWORD dwFunIndex = NULL;
            if (pThunkData->u1.AddressOfData > 0x80000000) {
                dwFunIndex = pThunkData->u1.Ordinal & 0xffff;
            }
            else {
                dwFunIndex = (DWORD)pDosHeader + pThunkData->u1.AddressOfData + 2;
            }

            // 填写IAT表
            *(DWORD*)pIat = (DWORD)MyGetProcAddress(hModule, (LPCSTR)dwFunIndex);
            pThunkData++;
            pIat++;
        }
        pImport++;
    }

}


void StretchPE(LPVOID lpDst, LPVOID lpFileBuff) {
    char szKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };

    HMODULE hKernel32 = MyGetModuleBase(szKernel32);
    PFN_VIRTUALPROTECT  pfnVirtualProtect = (PFN_VIRTUALPROTECT)MyGetProcAddress(hKernel32, szVirtualProtect);

    // PE格式解析
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuff;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    // 修改内存权限
    DWORD dwOldProtect;
    pfnVirtualProtect(lpDst, pOptionHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 拷贝PE头
    MyMemCopy(lpDst, lpFileBuff, pOptionHeader->SizeOfHeaders);

    // 拷贝节表
    for (int i = 0; i < pFileHeader->NumberOfSections; ++i) {
        if (pSectionHeader->SizeOfRawData != 0) {
            MyMemCopy((char*)lpDst + pSectionHeader->VirtualAddress, 
                      (char*)lpFileBuff + pSectionHeader->PointerToRawData, 
                       pSectionHeader->SizeOfRawData);
        }
        pSectionHeader++;
    }
}


void MyZeroMem(void* lpDstAddress, int dwSize) {
    __asm {
        cld;
        mov edi, lpDstAddress;
        mov ecx, dwSize;
        mov eax, 0
        rep stosb;
    }
}

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

BOOL CmpPascalStrWithCStr(const char* pPascalStr, const char* pCStr, int nCStrSize) {
    int nIndex = 0;
    for (int i = 0; i < nCStrSize; ++i) {
        if (pCStr[i] != pPascalStr[nIndex] && pCStr[i] != (pPascalStr[nIndex] + 32)) {
            return FALSE;
        }
        nIndex += 2;
    }

    if (pPascalStr[nIndex] != '\0') {
        return FALSE;
    }
    return TRUE;
}


/*
函数功能：在TEB中，通过模块名称/模块路径获取模块句柄
参数：
  lpModuleName：模块名称/模块路径
返回值：
  成功返回模块句柄
  失败返回NULL，模块信息表中可能没有要查找的模块
注意：
  当传入参数为NULL时，表示获取主模块的句柄
*/
HMODULE MyGetModuleBase(LPCSTR lpModuleName) {
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

    char szKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };

    MY_LIST_ENTRY* pCurNode = NULL;
    MY_LIST_ENTRY* pPrevNode = NULL;
    MY_LIST_ENTRY* pNextNode = NULL;
    MY_LIST_ENTRY* pFirstNode = NULL;

    // 通过TEB获取模块信息表
    __asm {
        pushad;
        mov eax, fs: [0x18] ;   //teb
        mov eax, [eax + 0x30];  //peb
        mov eax, [eax + 0x0c];  //_PEB_LDR_DATA
        mov eax, [eax + 0x0c];  //模块信息表_LIST_ENTRY,主模块
        mov pCurNode, eax;
        mov ebx, dword ptr[eax];
        mov pPrevNode, ebx;
        mov ebx, dword ptr[eax + 0x4];
        mov pNextNode, ebx;
        popad;
    }

    pFirstNode = pCurNode;
    if (pCurNode == NULL || pPrevNode == NULL || pNextNode == NULL) {
        return NULL;
    }

    if (lpModuleName == NULL)
        return pCurNode->hInstance;

    // 遍历模块信息表
    MY_LIST_ENTRY* pTmp = NULL;
    while (pPrevNode != pFirstNode) {
        // 比较模块名称
        if (CmpPascalStrWithCStr((char*)pCurNode->pUnicodeFileName, lpModuleName, MyStrLen(lpModuleName))) {
            return pCurNode->hInstance;
        }

        // 比较模块路径
        if (CmpPascalStrWithCStr((char*)pCurNode->pUnicodePathName, lpModuleName, MyStrLen(lpModuleName))) {
            return pCurNode->hInstance;
        }
        pTmp = pPrevNode;
        pCurNode = pTmp;
        pPrevNode = pTmp->Flink;
        pNextNode = pTmp->Blink;
    }

    HMODULE hKernel32 = MyGetModuleBase(szKernel32);
    PFN_LOADLIBRARYA pfnLoadLibraryA = (PFN_LOADLIBRARYA)MyGetProcAddress(hKernel32, szLoadLibraryA);
    return pfnLoadLibraryA(lpModuleName); // 模块信息表中没有要查找的模块，调用系统LoadLibrary
}


/*
函数功能：通过函数名称/序号，获取函数地址
参数：
  hInst：     模块句柄
  lpProcName：函数名称/序号
返回值：
  成功返回查找到的函数地址
  失败返回NULL
*/
LPVOID MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName) {
    if (hInst == NULL || lpProcName == NULL)
        return NULL;

    // 对模块基址进行PE格式解析
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader +
        pFileHeader->SizeOfOptionalHeader);

    // 获取导出表的位置
    DWORD dwExportTableRva = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dwExportTableSize = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((char*)hInst + dwExportTableRva);
    DWORD dwExportEnd = (DWORD)pExport + dwExportTableSize; // 导入表的大小，用来判断是否为导出转发

    // 获取内存中，导出表中三个表格的地址
    DWORD dwAddressOfFunctionsRva = pExport->AddressOfFunctions;
    DWORD dwAddressOfNamesRva = pExport->AddressOfNames;
    DWORD dwAddressOfNameOrdinalsRva = pExport->AddressOfNameOrdinals;
    DWORD* pAddressOfFunctions = (DWORD*)(dwAddressOfFunctionsRva + (char*)hInst);
    DWORD* pAddressOfNames = (DWORD*)(dwAddressOfNamesRva + (char*)hInst);
    WORD* pAddressOfNameOrdinals = (WORD*)(dwAddressOfNameOrdinalsRva + (char*)hInst);

    DWORD dwIndex = -1;
    // 首先判断是名称还是序号,得到AddressOfFunctions的索引
    if (((DWORD)lpProcName & 0xFFFF0000) > 0) {
        // 名称查询，首先获取目标名称在导出名称表中的索引
        for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
            char* pName = (pAddressOfNames[i] + (char*)hInst);
            if (MyMemCmp(pName, (void*)lpProcName, MyStrLen(lpProcName)) == 0 &&
                MyStrLen(lpProcName) == MyStrLen(pName)) {
                // 找到目标字符串，同下标去访问名称序号表，得到最终的索引
                dwIndex = pAddressOfNameOrdinals[i];
            }
        }
    }
    else {
        // 使用序号查询时，the high-order word must be zero
        dwIndex = ((DWORD)lpProcName & 0xFFFF) - pExport->Base;
    }

    if (dwIndex == -1) {
        return NULL;
    }

    // 判断是否为导出转发
    DWORD dwProcAddr = (DWORD)(pAddressOfFunctions[dwIndex] + (char*)hInst);
    if ((dwProcAddr >= (DWORD)pExport) && (dwProcAddr < dwExportEnd)) {
        // 如果是导出转发，则需要递归查找，对应的地址保存的转发的dll名称和函数名称
        char dllName[MAXBYTE];
        MyZeroMem(dllName, MAXBYTE);
        __asm {
            pushad;
            mov esi, dwProcAddr;
            lea edi, dllName;
            mov ecx, MAXBYTE;
            xor edx, edx;
        LOOP_BEGIN:
            mov dl, byte ptr ds : [esi] ;
            cmp dl, 0x2e;
            jz LOOP_END;
            movsb;
            loop LOOP_BEGIN;
        LOOP_END:
            inc esi;
            mov dwProcAddr, esi;
            popad;
        }

        HMODULE hModule = MyGetModuleBase(dllName);
        return MyGetProcAddress(hModule, (char*)dwProcAddr); // 递归查找
    }
    return (LPVOID)dwProcAddr;
}
