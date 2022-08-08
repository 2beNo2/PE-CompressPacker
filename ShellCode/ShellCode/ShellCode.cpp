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
    char szUser32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' }; 
    char szKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    char szCabinet[] = { 'C', 'a', 'b', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', '\0' };

    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    char szVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    char szCreateDecompressor[] = { 'C', 'r', 'e', 'a', 't', 'e', 'D', 'e', 'c', 'o', 'm', 'p', 'r', 'e', 's', 's', 'o', 'r', '\0' };

    HMODULE hKernel32 = MyGetModuleBase(szKernel32);
    HMODULE hUser32 = MyGetModuleBase(szUser32);
    HMODULE hCabinet = MyGetModuleBase(szCabinet);
    PFN_LOADLIBRARYA  pfnLoadLibraryA = (PFN_LOADLIBRARYA)MyGetProcAddress(hKernel32, szLoadLibraryA);
    PFN_VIRTUALALLOC pfnVirtualAlloc = (PFN_VIRTUALALLOC)MyGetProcAddress(hKernel32, szVirtualAlloc);
    PFN_CREATEDECOMPRESSOR pfn = (PFN_CREATEDECOMPRESSOR)MyGetProcAddress(hCabinet, szCreateDecompressor);


    // 当前程序的PE格式解析
    HMODULE hMain = MyGetModuleBase(NULL);
    PIMAGE_DOS_HEADER pPackerDosHeader = (PIMAGE_DOS_HEADER)hMain;
    PIMAGE_NT_HEADERS pPackerNtHeader = (PIMAGE_NT_HEADERS)((char*)pPackerDosHeader + pPackerDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pPackerFileHeader = (PIMAGE_FILE_HEADER)(&pPackerNtHeader->FileHeader);
    PIMAGE_OPTIONAL_HEADER pPackerOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pPackerNtHeader->OptionalHeader);
    PIMAGE_SECTION_HEADER pPackerSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pPackerOptionHeader + pPackerFileHeader->SizeOfOptionalHeader);

    // 解压数据
    DWORD dwComDataSize = pPackerSectionHeader[SHI_COM].PointerToLinenumbers; // 压缩数据的大小
    PBYTE pComDataBuff = (PBYTE)((char*)pPackerDosHeader + pPackerSectionHeader[SHI_COM].PointerToRawData); // 压缩数据的内存地址
    DWORD dwDeComDataSize = pPackerSectionHeader[SHI_COM].PointerToRelocations; // 解压后数据的大小
    LPVOID lpDecomDataBuff = pfnVirtualAlloc(NULL, dwDeComDataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE); //  解压后数据的内存地址
    
    /*
    
    //  Create an XpressHuff decompressor.
        Success = CreateDecompressor(
            COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
            NULL,                           //  Optional allocation routine
            &Decompressor);                 //  Handle

        if (!Success)
        {
            wprintf(L"Cannot create a decompressor: %d.\n", GetLastError());
            goto done;
        }

        //  Query decompressed buffer size.
        Success = Decompress(
            Decompressor,                //  Compressor Handle
            CompressedBuffer,            //  Compressed data
            InputFileSize,               //  Compressed data size
            NULL,                        //  Buffer set to NULL
            0,                           //  Buffer size set to 0
            &DecompressedBufferSize);    //  Decompressed Data size

        //  Allocate memory for decompressed buffer.
        if (!Success)
        {
            DWORD ErrorCode = GetLastError();

            // Note that the original size returned by the function is extracted 
            // from the buffer itself and should be treated as untrusted and tested
            // against reasonable limits.
            if (ErrorCode != ERROR_INSUFFICIENT_BUFFER) 
            {
                wprintf(L"Cannot decompress data: %d.\n",ErrorCode);
                goto done;
            }

            DecompressedBuffer = (PBYTE)malloc(DecompressedBufferSize);
            if (!DecompressedBuffer)
            {
                wprintf(L"Cannot allocate memory for decompressed buffer.\n");
                goto done;
            }           
        }
        
        StartTime = GetTickCount64();

        //  Decompress data and write data to DecompressedBuffer.
        Success = Decompress(
            Decompressor,               //  Decompressor handle
            CompressedBuffer,           //  Compressed data
            InputFileSize,              //  Compressed data size
            DecompressedBuffer,         //  Decompressed buffer
            DecompressedBufferSize,     //  Decompressed buffer size
            &DecompressedDataSize);     //  Decompressed data size

        if (!Success)
        {
            wprintf(L"Cannot decompress data: %d.\n", GetLastError());
            goto done;
        }
    */

    // 拉伸PE


    // 修复IAT


    // reloc


    // 是否存在TLS


    // 跳到入口点


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
    return NULL;
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
    char szKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' };
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };

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
            if (MyMemCmp(pName, (void*)lpProcName, MyStrLen(lpProcName)) == 0) {
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
        if (hModule == NULL) {
            HMODULE hKernel32 = MyGetModuleBase(szKernel32);
            PFN_LOADLIBRARYA  pfnLoadLibraryA = (PFN_LOADLIBRARYA)MyGetProcAddress(hKernel32, szLoadLibraryA);
            hModule = pfnLoadLibraryA(dllName); // 模块信息表中没有要查找的模块，调用系统LoadLibrary
        }
        return MyGetProcAddress(hModule, (char*)dwProcAddr); // 递归查找
    }

    return (void*)dwProcAddr;
}
