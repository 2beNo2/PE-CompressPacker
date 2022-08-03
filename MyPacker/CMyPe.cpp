#include "pch.h"
#include "CMyPe.h"

CMyPe::CMyPe()
{
  Init();
}

CMyPe::CMyPe(void* pFileBuff)
{
  Init();
  InitPeFormat(pFileBuff);
  m_bIsMemInit = 1;
}

CMyPe::CMyPe(const char* strFilePath)
{
  Init();
  InitPeFormat(strFilePath);
  m_bIsMemInit = 0;
}

CMyPe::~CMyPe()
{
  if (m_lpFileBuff != NULL && m_bIsMemInit != 1)
  {
    ::UnmapViewOfFile(m_lpFileBuff);
    m_lpFileBuff = NULL;
  }

  if (m_hFileMap != NULL)
  {
    ::CloseHandle(m_hFileMap);
    m_hFileMap = NULL;
  }

  if (m_hFile != INVALID_HANDLE_VALUE)
  {
    ::CloseHandle(m_hFile);
    m_hFile = INVALID_HANDLE_VALUE;
  }
}

int CMyPe::IsPeFile(void* pFileBuff)
{
  // 判断是否PE文件
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuff;
  if (pDosHeader->e_magic != 'ZM')
  {
    return FILE_NOT_PE;
  }
  PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pFileBuff + pDosHeader->e_lfanew);
  if (pNtHeader->Signature != 'EP')
  {
    return FILE_NOT_PE;
  }

  return FILE_IS_PE;
}

int CMyPe::IsPeFile(const char* strFilePath)
{
  // 打开文件
  HANDLE hFile = ::CreateFile(strFilePath,            // 文件路径
                              GENERIC_READ | GENERIC_WRITE,  // 文件的打开方式
                              FILE_SHARE_READ,        // 共享模式，其他文件可读
                              NULL,                   // 安全属性，用于确定返回的句柄是否可以被子进程继承
                              OPEN_EXISTING,          // 打开方式
                              FILE_ATTRIBUTE_NORMAL,  // 文件属性
                              NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    return FIlE_OPEN_FAILD;
  }

  // 获取MZ标志
  WORD wMzMagic = 0;
  DWORD dwNumberOfBytesRead = 0;
  int nRet = ::ReadFile(hFile, &wMzMagic, sizeof(WORD), &dwNumberOfBytesRead, NULL);
  if (nRet == 0) { goto OPENFAILD; }
  if (wMzMagic != 'ZM') { goto NOTPE; }

  // 获取PE标志
  DWORD dwOffset = 0;
  WORD wPeMagic = 0;
  DWORD dwPtr = ::SetFilePointer(hFile, 0x3c, NULL, FILE_BEGIN);
  if (dwPtr == INVALID_SET_FILE_POINTER) { goto OPENFAILD; }

  nRet = ::ReadFile(hFile, &dwOffset, sizeof(DWORD), &dwNumberOfBytesRead, NULL);
  if (nRet == 0){ goto OPENFAILD; }

  dwPtr = ::SetFilePointer(hFile, dwOffset, NULL, FILE_BEGIN);
  if (dwPtr == INVALID_SET_FILE_POINTER){ goto OPENFAILD; }

  nRet = ::ReadFile(hFile, &wPeMagic, sizeof(wPeMagic), &dwNumberOfBytesRead, NULL);
  if (nRet == 0){ goto OPENFAILD; }
  if (wPeMagic != 'EP'){ goto NOTPE; }

  ::CloseHandle(hFile);
  return FILE_IS_PE;

OPENFAILD:
  ::CloseHandle(hFile);
  return FIlE_OPEN_FAILD;

NOTPE:
  ::CloseHandle(hFile);
  return FILE_NOT_PE;
}

int CMyPe::WriteMemoryToFile(void* pFileBuff, int nFileSize, const char* strFilePath)
{
  // 打开文件
  HANDLE hFile = ::CreateFile(strFilePath,            // 文件路径
                              GENERIC_WRITE,          // 文件的打开方式
                              FILE_SHARE_READ,        // 共享模式，其他文件可读
                              NULL,                   // 安全属性，用于确定返回的句柄是否可以被子进程继承
                              CREATE_ALWAYS,          // 打开方式
                              FILE_ATTRIBUTE_NORMAL,  // 文件属性
                              NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    return FIlE_OPEN_FAILD;
  }

  DWORD dwNumberOfBytesWritten = 0;
  if (!::WriteFile(hFile, pFileBuff, nFileSize, &dwNumberOfBytesWritten, NULL))
  {
    ::CloseHandle(hFile);
    return FIlE_WRITE_FAILD;
  }

  ::CloseHandle(hFile);
  return FIlE_WRITE_SUC;
}

void CMyPe::Init()
{
  m_lpFileBuff = NULL;
  m_pDosHeader = NULL;
  m_pNtHeader = NULL;
  m_pFileHeader = NULL;
  m_pOptionHeader = NULL;
  m_pSectionHeader = NULL;
  m_pExportDirectory = NULL;
  m_pImportDirectory = NULL;
  m_pResourceDirectory = NULL;
  m_pRelocDirectory = NULL;
  m_pTlsDirectory = NULL;
  m_dwExportSize = 0;
  m_dwImportSize = 0;
  m_dwRelocSize = 0;

  m_wNumberOfSections = 0;
  m_dwAddressOfEntryPoint = 0;
  m_dwImageBase = 0;
  m_dwSectionAlignment = 0;
  m_dwFileAlignment = 0;
  m_dwSizeOfImage = 0;
  m_dwSizeOfHeaders = 0;
  m_dwNumberOfRvaAndSizes = 0;

  m_hFile = INVALID_HANDLE_VALUE;
  m_dwFileSize = 0;
  m_hFileMap = NULL;
  m_bIsMemInit = 0;
}

void CMyPe::InitPeFormat(void* pFileBuff)
{
  if (IsPeFile(pFileBuff) != FILE_IS_PE)
  {
    return;
  }
  m_lpFileBuff = pFileBuff;
  m_pDosHeader = (PIMAGE_DOS_HEADER)pFileBuff;
  m_pNtHeader = (PIMAGE_NT_HEADERS)((char*)pFileBuff + m_pDosHeader->e_lfanew);
  m_pFileHeader = (PIMAGE_FILE_HEADER)(&m_pNtHeader->FileHeader);
  m_pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&m_pNtHeader->OptionalHeader);
  m_pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)m_pOptionHeader + m_pFileHeader->SizeOfOptionalHeader);

  m_wNumberOfSections = m_pFileHeader->NumberOfSections;
  m_dwAddressOfEntryPoint = m_pOptionHeader->AddressOfEntryPoint;
  m_dwImageBase = m_pOptionHeader->ImageBase;
  m_dwSectionAlignment = m_pOptionHeader->SectionAlignment;
  m_dwFileAlignment = m_pOptionHeader->FileAlignment;
  m_dwSizeOfImage = m_pOptionHeader->SizeOfImage;
  m_dwSizeOfHeaders = m_pOptionHeader->SizeOfHeaders;
  m_dwNumberOfRvaAndSizes = m_pOptionHeader->NumberOfRvaAndSizes;

  // 导出表
  DWORD dwExportRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  m_dwExportSize = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  DWORD dwFa = Rva2Fa(dwExportRva, pFileBuff);
  if (dwFa == -1) 
  {
    m_pExportDirectory = NULL;
  }
  else
  {
    m_pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwFa + (char*)m_lpFileBuff);
  }
  

  // 导入表
  DWORD dwImportRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  m_dwImportSize = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
  dwFa = Rva2Fa(dwImportRva, pFileBuff);
  if (dwFa == -1)
  {
    m_pImportDirectory = NULL;
  }
  else
  {
    m_pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(dwFa + (char*)m_lpFileBuff);
  }

  // 资源表
  DWORD dwResourceRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
  dwFa = Rva2Fa(dwResourceRva, pFileBuff);
  if (dwFa == -1)
  {
    m_pResourceDirectory = NULL;
  }
  else
  {
    m_pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)(dwFa + (char*)m_lpFileBuff);
  }

  // 重定位表
  DWORD dwRelocRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
  m_dwRelocSize = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
  dwFa = Rva2Fa(dwRelocRva, pFileBuff);
  if (dwFa == -1)
  {
    m_pRelocDirectory = NULL;
  }
  else
  {
    m_pRelocDirectory = (PIMAGE_BASE_RELOCATION)(dwFa + (char*)m_lpFileBuff);
  }

  // TLS表
  DWORD dwTlsRva = m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
  dwFa = Rva2Fa(dwTlsRva, pFileBuff);
  if (dwFa == -1)
  {
    m_pTlsDirectory = NULL;
  }
  else
  {
    m_pTlsDirectory = (PIMAGE_TLS_DIRECTORY)(dwFa + (char*)m_lpFileBuff);
  }
}

void CMyPe::InitPeFormat(const char* strFilePath)
{
  if (IsPeFile(strFilePath) != FILE_IS_PE)
  {
    return;
  }
  // 打开文件
  m_hFile = ::CreateFile(strFilePath,           // 文件路径
                        GENERIC_READ | GENERIC_WRITE,  // 文件的打开方式
                        FILE_SHARE_READ,        // 共享模式，其他文件可读
                        NULL,                   // 安全属性，用于确定返回的句柄是否可以被子进程继承
                        OPEN_EXISTING,          // 打开方式
                        FILE_ATTRIBUTE_NORMAL,  // 文件属性
                        NULL);
  if (m_hFile == INVALID_HANDLE_VALUE)
  {
    return;
  }

  // 获取文件大小
  m_dwFileSize = ::GetFileSize(m_hFile, NULL);

  // 创建文件映射对象
  m_hFileMap = ::CreateFileMapping(m_hFile,  // 文件句柄
                                    NULL,    // 安全属性，用于确定返回的句柄是否可以被子进程继承
                                    PAGE_READWRITE, // 映射后内存也的内存属性
                                    NULL,    // 大于4G时设置
                                    m_dwFileSize, // 映射大小
                                    NULL);   // 文件映射对象的名称，设置后可用于进程间通信
  if (m_hFileMap == NULL)
  {
    return;
  }

  // 将文件映射到内存
  m_lpFileBuff = ::MapViewOfFile(m_hFileMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
  if (m_lpFileBuff == NULL) {
    return;
  }

  InitPeFormat(m_lpFileBuff);
}

PVOID CMyPe::GetExportName(DWORD dwOrdinal)
{
  DWORD dwNumberOfNames = m_pExportDirectory->NumberOfNames;
  if(dwNumberOfNames == 0)
  {
    return nullptr;
  }

  DWORD dwAddressOfNames = m_pExportDirectory->AddressOfNames;
  DWORD* pAddressOfNames = (DWORD*)(Rva2Fa(dwAddressOfNames, m_lpFileBuff) + (char*)m_lpFileBuff);

  DWORD dwAddressOfNameOrdinals = m_pExportDirectory->AddressOfNameOrdinals;
  WORD* pAddressOfNameOrdinals = (WORD*)(Rva2Fa(dwAddressOfNameOrdinals, m_lpFileBuff) + (char*)m_lpFileBuff);

  for(DWORD i = 0; i < dwNumberOfNames; ++i)
  {
    if(pAddressOfNameOrdinals[i] == dwOrdinal)
    {
      DWORD dwNameAddressRva = pAddressOfNames[i];
      return (LPVOID)(Rva2Fa(dwNameAddressRva, m_lpFileBuff) + (char*)m_lpFileBuff);
    }
  }
  return nullptr;
}


/*
函数功能：通过函数名称/序号，获取函数地址
参数：
  hInst：     模块句柄
  lpProcName：函数名称/序号
返回值：
  返回查找到的函数地址
*/
LPVOID CMyPe::MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName)
{
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hInst;
  PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
  PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
  PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
  PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

  DWORD dwExportTableRva = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  DWORD dwExportTableSize = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

  PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((char*)hInst + dwExportTableRva);
  DWORD dwExportEnd = (DWORD)pExport + dwExportTableSize;
  
  // 获取内存中，导出表中三个表格的地址
  DWORD dwAddressOfFunctionsRva = pExport->AddressOfFunctions;
  DWORD dwAddressOfNamesRva = pExport->AddressOfNames;
  DWORD dwAddressOfNameOrdinalsRva = pExport->AddressOfNameOrdinals;
  DWORD* pAddressOfFunctions = (DWORD*)(dwAddressOfFunctionsRva + (char*)hInst);
  DWORD* pAddressOfNames = (DWORD*)(dwAddressOfNamesRva + (char*)hInst);
  WORD*  pAddressOfNameOrdinals = (WORD*)(dwAddressOfNameOrdinalsRva + (char*)hInst);

  DWORD dwIndex = -1;
  // 首先判断是名称还是序号,得到AddressOfFunctions的索引
  if (((DWORD)lpProcName & 0xFFFF0000) > 0)
  {
    // 名称查询，首先获取目标名称在导出名称表中的索引
    // 应该使用其他查找算法，此次暂时先使用简单的字符串比较
    for (DWORD i = 0; i < pExport->NumberOfNames; ++i)
    {
      char* pName = (pAddressOfNames[i] + (char*)hInst);
      if (strcmp(pName, lpProcName) == 0)
      {
        // 找到目标字符串，同下标去访问名称序号表，得到最终的索引
        dwIndex = pAddressOfNameOrdinals[i];
      }
    }
  }
  else
  {
    // 使用序号查询时，the high-order word must be zero
    dwIndex = ((DWORD)lpProcName & 0xFFFF) - pExport->Base;
  }

  if (dwIndex == -1)
  {
    return nullptr;
  }

  // 判断是否为导出转发
  DWORD dwProcAddr = (DWORD)(pAddressOfFunctions[dwIndex] + (char*)hInst);
  if ((dwProcAddr >= (DWORD)pExport) && (dwProcAddr < dwExportEnd))
  {
    // 如果是导出转发，则需要递归查找，对应的地址保存的转发的dll名称和函数名称
    char dllName[MAXBYTE] = { 0 };
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
    return CMyPe::MyGetProcAddress(hModule, (char*)dwProcAddr); // 递归查找
  }

  return (void*)dwProcAddr;
}



/*
函数功能：通过函数地址获取函数名称/序号
参数：
  pfnAddr：目标函数地址
返回值：
  返回函数名称或序号
*/
LPVOID CMyPe::MyGetProcFunName(LPVOID pfnAddr)
{
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
  }
  */
  struct _LIST_ENTRY
  {
    struct _LIST_ENTRY* Flink;  //0x0
    struct _LIST_ENTRY* Blink;  //0x4
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

  _LIST_ENTRY* pCurNode = NULL;
  _LIST_ENTRY* pPrevNode = NULL;
  _LIST_ENTRY* pNextNode = NULL;

  // 通过TEB获取模块信息表
  __asm {
    pushad;
    mov eax, fs: [0x18] ;   //teb
    mov eax, [eax + 0x30];  //peb
    mov eax, [eax + 0x0c];  //_PEB_LDR_DATA
    mov eax, [eax + 0x0c];  //模块信息表_LIST_ENTRY,主模块
    mov pCurNode, eax;
    mov ebx, dword ptr [eax];
    mov pPrevNode, ebx;
    mov ebx, dword ptr[eax + 0x4];
    mov pNextNode, ebx;
    popad;
  }
  
  if (pCurNode == NULL || pPrevNode == NULL || pNextNode == NULL)
  {
    return NULL;
  }

  // 遍历模块信息表，在模块的导出表中查找
  HMODULE hModule = NULL;
  _LIST_ENTRY* pTmp = NULL;
  int nSizeOfImage = 0;
  while (pCurNode != pPrevNode)
  {
    hModule = pCurNode->hInstance;
    nSizeOfImage = pCurNode->nSizeOfImage;
    if (((DWORD)pfnAddr > (DWORD)hModule) &&
       ((DWORD)pfnAddr < (DWORD)hModule + nSizeOfImage))
    {
      // 找到函数地址所在的模块，再进行导出表解析
      PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
      PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
      PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
      PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);

      DWORD dwExportTableRva  = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((char*)hModule + dwExportTableRva);

      // 获取内存中，导出表中三个表格的地址
      DWORD dwAddressOfFunctionsRva = pExport->AddressOfFunctions;
      DWORD dwAddressOfNamesRva = pExport->AddressOfNames;
      DWORD dwAddressOfNameOrdinalsRva = pExport->AddressOfNameOrdinals;
      DWORD* pAddressOfFunctions = (DWORD*)(dwAddressOfFunctionsRva + (char*)hModule);
      DWORD* pAddressOfNames = (DWORD*)(dwAddressOfNamesRva + (char*)hModule);
      WORD*  pAddressOfNameOrdinals = (WORD*)(dwAddressOfNameOrdinalsRva + (char*)hModule);

      // 首先获取函数地址在导出地址表中的索引
      DWORD dwIndex = -1;
      for (DWORD i = 0; i < pExport->NumberOfFunctions; ++i)
      {
        if ((pAddressOfFunctions[i] + (char*)hModule) == pfnAddr)
        {
          dwIndex = i;
          break;
        }
      }
      if (dwIndex == -1) return NULL;

      // 查找索引在名称序号表中是否存在，存在则表示是名称导出，否则是序号导出
      for (DWORD i = 0; i < pExport->NumberOfNames; ++i)
      {
        if (pAddressOfNameOrdinals[i] == dwIndex)
        {
          return pAddressOfNames[i] + (char*)hModule;
        }
      }
      return (LPVOID)(dwIndex + pExport->Base);
    }

    pTmp = pPrevNode;
    pCurNode = pTmp;
    pPrevNode = pTmp->Flink;
    pNextNode = pTmp->Blink;
  }
  return NULL;
}

DWORD CMyPe::GetAlignSize(DWORD dwDataSize, DWORD dwAlign)
{
  if (dwDataSize == 0) return 0;
  DWORD dwMod = dwDataSize % dwAlign;
  if (dwMod == 0)
  {
    return dwDataSize;
  }
  return (dwMod + 1) * dwAlign;
}

/*
函数功能：新增节表
参数：
  lpOldFileBuff：PE文件的内存地址
  dwOldFileSize：PE文件的原始大小
  lpDataBuff   ：新增节表的数据
  dwDataSize   ：新增节表的数据的大小
返回值：
  新增节表成功后，PE文件新的内存地址
注意：
  dwDataSize = 0 时，增加一个没有文件映射的节
*/
LPVOID CMyPe::AddSection(LPVOID lpOldFileBuff, DWORD dwOldFileSize, LPVOID lpDataBuff, DWORD dwDataSize)
{
  // PE格式解析
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpOldFileBuff;
  PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
  PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
  PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
  PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

  // 计算新文件的大小
  DWORD dwNewFileSize = dwOldFileSize + GetAlignSize(dwDataSize, pOptionHeader->FileAlignment);

  // 申请新的内存，将旧的文件内存和新增节表数据拷贝过去
  LPVOID lpNewFileBuff = malloc(dwNewFileSize);
  if (lpNewFileBuff == NULL)
  {
    return NULL;
  }
  ::RtlZeroMemory(lpNewFileBuff, dwNewFileSize);

  memcpy(lpNewFileBuff, lpOldFileBuff, dwOldFileSize);
  if (lpDataBuff != NULL) 
  {
    memcpy(((char*)lpNewFileBuff + dwOldFileSize), lpDataBuff, dwDataSize);
  }
 
  // 检查PE头是否有足够空间增加节表项
  PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)lpNewFileBuff;
  PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)((char*)pNewDosHeader + pNewDosHeader->e_lfanew);
  PIMAGE_FILE_HEADER pNewFileHeader = (PIMAGE_FILE_HEADER)(&pNewNtHeader->FileHeader);
  PIMAGE_OPTIONAL_HEADER pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNewNtHeader->OptionalHeader);
  PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pNewOptionHeader + pNewFileHeader->SizeOfOptionalHeader);

  DWORD dwReserved = pNewOptionHeader->SizeOfHeaders - 
                    ((DWORD)pNewSectionHeader + pNewFileHeader->NumberOfSections * 0x28 - (DWORD)pNewDosHeader);
  if (dwReserved < 0x28)
  {
    // 空间不足时，可以选择数据上移，占用DOS Stub的空间
    free(lpNewFileBuff);
    return NULL;
  }

  // 检查新增节表项的位置，数据是否为0
  IMAGE_SECTION_HEADER structAddSection = { 0 };
  PIMAGE_SECTION_HEADER pAddSectionHeader = pNewSectionHeader + pNewFileHeader->NumberOfSections;
  if (memcmp(pAddSectionHeader, &structAddSection, sizeof(IMAGE_SECTION_HEADER)) != NULL)
  {
    // 可能会覆盖数据时，也可以选择数据上移，占用DOS Stub的空间
    free(lpNewFileBuff);
    return NULL;
  }

  // 构造新的节表项
  DWORD dwLastSectionHeaderIndex = pNewFileHeader->NumberOfSections - 1;
  structAddSection.Misc.VirtualSize = GetAlignSize(dwDataSize, pOptionHeader->SectionAlignment);
  structAddSection.VirtualAddress = pNewSectionHeader[dwLastSectionHeaderIndex].VirtualAddress +
    GetAlignSize(pNewSectionHeader[dwLastSectionHeaderIndex].Misc.VirtualSize, pOptionHeader->SectionAlignment);

  structAddSection.SizeOfRawData = GetAlignSize(dwDataSize, pOptionHeader->FileAlignment);
  structAddSection.PointerToRawData = pNewSectionHeader[dwLastSectionHeaderIndex].PointerToRawData +
    GetAlignSize(pNewSectionHeader[dwLastSectionHeaderIndex].SizeOfRawData, pOptionHeader->FileAlignment);

  // 拷贝新节表项到节表末尾
  memcpy(pAddSectionHeader, &structAddSection, sizeof(IMAGE_SECTION_HEADER));
  
  // 修改PE中相关字段：SizeOfImage NumberOfSections
  pNewOptionHeader->SizeOfImage = pAddSectionHeader->VirtualAddress + pAddSectionHeader->Misc.VirtualSize;
  pNewFileHeader->NumberOfSections += 1;

  return lpNewFileBuff;
}


/*
函数功能：导入表注入
参数：
  lpFileBuff：PE文件的内存地址
  lpDllName ：注入的dll名称
  lpProcName：注入的函数名称
返回值：
  注入成功后，PE文件新的内存地址
*/
LPVOID CMyPe::MyAddImportTableItem(LPVOID lpFileBuff, LPCSTR lpDllName, LPCSTR lpProcName)
{
  // PE格式解析
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuff;
  PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
  PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
  PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
  PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

  // 获取旧的导入表的位置和项数
  DWORD dwImportRva = pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
  DWORD dwImportFa = CMyPe::Rva2Fa(dwImportRva, lpFileBuff);
  LPVOID lpOldImportTable = (char*)lpFileBuff + dwImportFa;

  //
  DWORD dwOldImportCount = 0;
  IMAGE_IMPORT_DESCRIPTOR structAddImport = { 0 };
  PIMAGE_IMPORT_DESCRIPTOR lpTmp = (PIMAGE_IMPORT_DESCRIPTOR)lpOldImportTable;
  while (memcmp(lpTmp, &structAddImport, sizeof(IMAGE_IMPORT_DESCRIPTOR)) !=0)
  {
    dwOldImportCount++;
    lpTmp++;
  }

  // 增加一个新节，同时将原来的导入表拷贝到新节
  DWORD dwOldFileSize = pSectionHeader[pFileHeader->NumberOfSections - 1].SizeOfRawData +
    pSectionHeader[pFileHeader->NumberOfSections - 1].PointerToRawData;
  LPVOID lpNewFileBuff = CMyPe::AddSection(lpFileBuff, 
                                            dwOldFileSize,
                                            lpOldImportTable, 
                                            dwOldImportCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));
  if (lpNewFileBuff == NULL)
  {
    // 新增节表失败
    return NULL;
  }

  // 获取新增节表项
  PIMAGE_DOS_HEADER pNewDosHeader = (PIMAGE_DOS_HEADER)lpNewFileBuff;
  PIMAGE_NT_HEADERS pNewNtHeader = (PIMAGE_NT_HEADERS)((char*)pNewDosHeader + pNewDosHeader->e_lfanew);
  PIMAGE_FILE_HEADER pNewFileHeader = (PIMAGE_FILE_HEADER)(&pNewNtHeader->FileHeader);
  PIMAGE_OPTIONAL_HEADER pNewOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNewNtHeader->OptionalHeader);
  PIMAGE_SECTION_HEADER pNewSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pNewOptionHeader + pNewFileHeader->SizeOfOptionalHeader);
  PIMAGE_SECTION_HEADER pAddSectionHeader = &pNewSectionHeader[pNewFileHeader->NumberOfSections - 1];
  DWORD dwAddSectionVirtualAddress = pAddSectionHeader->VirtualAddress;
  DWORD dwAddSectionPointerToRawData = pAddSectionHeader->PointerToRawData;

  // 构造导入表需要的dll名称和ThunkData
  PIMAGE_IMPORT_DESCRIPTOR pNewImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pNewDosHeader + dwAddSectionPointerToRawData);

  PIMAGE_IMPORT_DESCRIPTOR pNewImportTableItem = pNewImportTable + dwOldImportCount;
  PVOID pDllName  = (char*)(pNewImportTableItem + 2);
  PVOID pProcName = (char*)pDllName + strlen(lpDllName) + 0x10;
  PVOID pThunkData = (char*)pProcName + strlen(lpProcName) + 0x10;
  memcpy(pDllName, lpDllName, strlen(lpDllName) + 1);
  memcpy((char*)pProcName + 2, lpProcName, strlen(lpProcName) + 1);
  *(DWORD*)pThunkData = (DWORD)pProcName - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;

  // 构造要增加的导入表表项，注意是Rva
  structAddImport.OriginalFirstThunk = NULL;
  structAddImport.Name = (DWORD)pDllName - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;
  structAddImport.FirstThunk = (DWORD)pThunkData - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;
  
  // 将新增的导入表表项写到导入表的最后
  memcpy(pNewImportTableItem, &structAddImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));

  // 修改数据目录中，导入表的Rva
  pNewOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 
      (DWORD)pNewImportTable - (DWORD)lpNewFileBuff - dwAddSectionPointerToRawData + dwAddSectionVirtualAddress;

  // 测试
  CMyPe::WriteMemoryToFile(lpNewFileBuff, 
    pAddSectionHeader->SizeOfRawData + (DWORD)pAddSectionHeader->PointerToRawData,
    TEXT("C:\\Users\\hc\\Desktop\\test\\1.out"));
  free(lpNewFileBuff);

  return NULL;
}

DWORD CMyPe::Rva2Fa(DWORD dwRva, LPVOID lpFileBuff)
{
  // PE格式解析
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpFileBuff;
  PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((char*)pDosHeader + pDosHeader->e_lfanew);
  PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(&pNtHeader->FileHeader);
  PIMAGE_OPTIONAL_HEADER pOptionHeader = (PIMAGE_OPTIONAL_HEADER)(&pNtHeader->OptionalHeader);
  PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((char*)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

  // 判断RVA是否有效,RVA是相对于模块基址的
  DWORD dwImageBase = (DWORD)lpFileBuff;
  DWORD dwVa = dwImageBase + dwRva;
  if (dwVa < dwImageBase || dwVa >= dwImageBase + pOptionHeader->SizeOfImage)
  {
    return -1;
  }
  
  // 遍历节表，获取FA
  for (int i = 0; i < pFileHeader->NumberOfSections; ++i)
  {
    DWORD dwVirtualAddress = pSectionHeader->VirtualAddress;  // 映射到内存的地址，RVA
    DWORD dwVirtualSize = pSectionHeader->Misc.VirtualSize;   // 映射到内存的数据大小，OS会将该值对齐后申请内存
    DWORD dwPointerToRawData = pSectionHeader->PointerToRawData; // 文件中数据的偏移
    DWORD dwSizeOfRawData = pSectionHeader->SizeOfRawData;    // 文件中数据对齐后大小

    if (dwRva >= dwVirtualAddress && dwRva < dwVirtualAddress + dwSizeOfRawData)
    {
      return dwRva - dwVirtualAddress + dwPointerToRawData;
    }
    pSectionHeader++;
  } 

  return -1;
}

LPVOID CMyPe::GetDosHeaderPointer()
{
  return m_pDosHeader;
}

LPVOID CMyPe::GetNtHeaderPointer()
{
  return m_pNtHeader;
}

LPVOID CMyPe::GetFileHeaderPointer()
{
  return m_pFileHeader;
}

LPVOID CMyPe::GetOptionHeaderPointer()
{
  return m_pOptionHeader;
}

LPVOID CMyPe::GetSectionHeaderPointer()
{
  return m_pSectionHeader;
}

LPVOID CMyPe::GetExportDirectoryPointer()
{
  return m_pExportDirectory;
}

DWORD CMyPe::GetExportDirectorySize()
{
  return m_dwExportSize;
}

LPVOID CMyPe::GetImportDirectoryPointer()
{
  return m_pImportDirectory;
}

LPVOID CMyPe::GetResourceDirectoryPointer()
{
  return m_pResourceDirectory;
}

LPVOID CMyPe::GetRelocDirectoryPointer()
{
  return m_pRelocDirectory;
}

DWORD CMyPe::GetRelocDirectorySize()
{
  return m_dwRelocSize;
}

LPVOID CMyPe::GetTlsDirectoryPointer()
{
  return m_pTlsDirectory;
}

WORD CMyPe::GetNumberOfSections()
{
  return m_wNumberOfSections;
}

DWORD CMyPe::GetAddressOfEntryPoint()
{
  return m_dwAddressOfEntryPoint;
}

DWORD CMyPe::GetImageBase()
{
  return m_dwImageBase;
}

DWORD CMyPe::GetSectionAlignment()
{
  return m_dwSectionAlignment;
}

DWORD CMyPe::GetFileAlignment()
{
  return m_dwFileAlignment;
}

DWORD CMyPe::GetSizeOfImage()
{
  return m_dwSizeOfImage;
}

DWORD CMyPe::GetSizeOfHeaders()
{
  return m_dwSizeOfHeaders;
}

DWORD CMyPe::GetNumberOfRvaAndSizes()
{
  return m_dwNumberOfRvaAndSizes;
}
