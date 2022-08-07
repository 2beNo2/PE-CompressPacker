// ShellCode.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "ShellCode.h"


/*
函数功能：通过模块名称/模块路径获取模块句柄
参数：
  lpModuleName：模块名称/模块路径
返回值：
  成功返回模块句柄
  失败返回NULL
*/
LPVOID MyGetModuleBase(LPCSTR lpModuleName) {
    if (lpModuleName == NULL)
        return NULL;

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

    // 模块名转换成Pascal字符串
    int nLen = MyStrLen(lpModuleName);

    // 遍历模块信息表
    MY_LIST_ENTRY* pTmp = NULL;
    while (pPrevNode != pFirstNode) {
        // 比较模块名称
        if (MyMemCmp((void*)lpModuleName, pCurNode->pUnicodeFileName, nLen) == 0 ) {
            //free(pDst);
            return pCurNode->hInstance;
        }

        // 比较模块路径
        if (MyMemCmp((void*)lpModuleName, pCurNode->pUnicodePathName, nLen) == 0 ) {
            //free(pDst);
            return pCurNode->hInstance;
        }

        pTmp = pPrevNode;
        pCurNode = pTmp;
        pPrevNode = pTmp->Flink;
        pNextNode = pTmp->Blink;
    }
    return NULL;
}


HMODULE GetMainModule() {
    HMODULE hMainModule = NULL;
    __asm
    {
        mov eax, fs: [0x18] ; //teb
        mov eax, [eax + 0x30]; //peb
        mov eax, [eax + 0x0C]; //_PEB_LDR_DATA
        mov eax, [eax + 0x0C]; //_LIST_ENTRY, 主模块
        mov eax, dword ptr[eax + 0x18]; //kernel32基址
        mov hMainModule, eax
    }
    return hMainModule;
}

HMODULE GetKernelBase() {
    HMODULE hKer32 = NULL;
    __asm
    {
        mov eax, fs: [0x18] ; //teb
        mov eax, [eax + 0x30]; //peb
        mov eax, [eax + 0x0C]; //_PEB_LDR_DATA
        mov eax, [eax + 0x0C]; //_LIST_ENTRY, 主模块
        mov eax, [eax]; //ntdll
        mov eax, [eax]; //kernel32
        mov eax, dword ptr[eax + 0x18]; //kernel32基址
        mov hKer32, eax
    }
    return hKer32;
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
        HMODULE hModule = ::LoadLibrary(dllName);  // 此处可优化为不使用API
        return MyGetProcAddress(hModule, (char*)dwProcAddr); // 递归查找
    }

    return (void*)dwProcAddr;
}


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
    typedef int (WINAPI* PFN_MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
    char szUser32[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', '\0' }; 
    char szMessageBox[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', '\0' };
    char szText[] = { 'T', 'e', 'x', 't', '\0' };
    HMODULE hUser32 = GetKernelBase();
    PFN_MESSAGEBOXA pfn = (PFN_MESSAGEBOXA)MyGetProcAddress(hUser32, szMessageBox);
    pfn(NULL, szText, szText, MB_OK);
}

