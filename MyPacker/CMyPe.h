#pragma once
#include <Windows.h>

class CMyPe
{
public:
  CMyPe();
  CMyPe(void* pFileBuff);
  CMyPe(const char* strFilePath);
  ~CMyPe();

public:
  enum {
    FIlE_OPEN_FAILD,
    FIlE_WRITE_FAILD,
    FIlE_WRITE_SUC,
    FILE_NOT_PE,
    FILE_IS_PE
  };
  static int IsPeFile(void* pFileBuff);
  static int IsPeFile(const char* strFilePath);
  static int WriteMemoryToFile(void* pFileBuff, int nFileSize, const char* strFilePath);

public:
  static DWORD  Rva2Fa(DWORD dwRva, LPVOID lpFileBuff);
  static DWORD  GetAlignSize(DWORD dwDataSize, DWORD dwAlign);  // 新增一个节
  static LPVOID AddSection(LPVOID lpOldFileBuff, DWORD dwOldFileSize, 
                    LPVOID lpDataBuff=NULL, DWORD dwDataSize=NULL); 

  // 导出表的利用
  static LPVOID MyGetProcFunName(LPVOID pfnAddr); // 通过函数地址获取函数名称/序号
  static LPVOID MyGetProcAddress(HMODULE hInst, LPCSTR lpProcName); // 自实现的GetProcAddress
  
  // 导入表的利用 导入表注入
  static LPVOID MyAddImportTableItem(LPVOID lpFileBuff, LPCSTR lpDllName, LPCSTR lpProcName); 

public:
  LPVOID GetExportName(DWORD dwOrdinal); // 通过序号来获取导出的名称

private:
  void Init();
  void InitPeFormat(void* pFileBuff);
  void InitPeFormat(const char* strFilePath);

private:
  HANDLE m_hFile;
  HANDLE m_hFileMap;
  DWORD  m_dwFileSize;
  LPVOID m_lpFileBuff;
  BOOL   m_bIsMemInit; // 如果构造时传入的是内存地址，则不需要取消文件映射

public:
  LPVOID GetDosHeaderPointer();
  LPVOID GetNtHeaderPointer();
  LPVOID GetFileHeaderPointer();
  LPVOID GetOptionHeaderPointer();
  LPVOID GetSectionHeaderPointer();

  LPVOID GetExportDirectoryPointer();
  LPVOID GetImportDirectoryPointer();
  LPVOID GetResourceDirectoryPointer();
  LPVOID GetRelocDirectoryPointer();
  LPVOID GetTlsDirectoryPointer();

  DWORD  GetExportDirectorySize();
  DWORD  GetRelocDirectorySize();

private:
  PIMAGE_DOS_HEADER      m_pDosHeader;
  PIMAGE_NT_HEADERS      m_pNtHeader;
  PIMAGE_FILE_HEADER     m_pFileHeader;
  PIMAGE_OPTIONAL_HEADER m_pOptionHeader;
  PIMAGE_SECTION_HEADER  m_pSectionHeader;

  PIMAGE_EXPORT_DIRECTORY   m_pExportDirectory;   // 导出表位于数据目录第0项
  PIMAGE_IMPORT_DESCRIPTOR  m_pImportDirectory;   // 导入表位于数据目录第1项
  PIMAGE_RESOURCE_DIRECTORY m_pResourceDirectory; // 资源表位于数据目录第2项
  PIMAGE_BASE_RELOCATION    m_pRelocDirectory;    // 重定位表位于数据目录第5项
  PIMAGE_TLS_DIRECTORY      m_pTlsDirectory;      // TLS位于数据目录第9项

  DWORD m_dwExportSize; // 导出表的size是有用的
  DWORD m_dwImportSize; // import使用全0结构结尾
  DWORD m_dwRelocSize;  // 重定位表的size是有用的，遍历时会用上

public:
  // PE结构部分重要字段
  WORD  GetNumberOfSections();
  DWORD GetAddressOfEntryPoint();
  DWORD GetImageBase();
  DWORD GetSectionAlignment();
  DWORD GetFileAlignment();
  DWORD GetSizeOfImage();
  DWORD GetSizeOfHeaders();
  DWORD GetNumberOfRvaAndSizes();

private:
  WORD  m_wNumberOfSections;      // 节表的个数
  DWORD m_dwAddressOfEntryPoint;  // 程序入口点，RVA
  DWORD m_dwImageBase;            // 程序的建议装载地址
  DWORD m_dwSectionAlignment;     // 在内存中的对齐 
  DWORD m_dwFileAlignment;        // 在文件中的对齐
  DWORD m_dwSizeOfImage;          // 文件载入内存并对齐后的大小
  DWORD m_dwSizeOfHeaders;        // PE头的大小
  DWORD m_dwNumberOfRvaAndSizes;  // 数据目录的个数
};

