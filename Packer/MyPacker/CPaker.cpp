#include "CPaker.h"
#include <compressapi.h>
#pragma comment(lib, "Cabinet.lib")


CPacker::CPacker() {
    m_PE = nullptr;
    m_pCompressData = NULL;
    m_pShellCode = NULL;
    m_pNewPeHeader = NULL;
}


CPacker::~CPacker() {
    if (m_PE != nullptr) {
        delete m_PE;
        m_PE = nullptr;
    }
}


BOOL CPacker::Pack(const char* pSrcPath, const char* pDstPath) {
	//1��PE ��ʽ����
	m_PE = new CMyPe(pSrcPath);

	//2����Ŀ��PE�ļ�����ѹ��
    if (!DoCompressData()) {
        return FALSE;
    }

    //3����ȡ�Ǵ���
    if (!GetShellCode()) {
        return FALSE;
    }

	//4�������µĽڱ�
    if (!RebuildSection()) {
        return FALSE;
    }

	//5��������PE�ļ���PEͷ
    if (!RebuildPeHeader()) {
        return FALSE;
    }

	//6��д�ļ�
    if (!WritePackerFile(pDstPath)) {
        return FALSE;
    }

    return TRUE;
}


BOOL CPacker::DoCompressData() {
    COMPRESSOR_HANDLE hCompressor = NULL;

    // ��ȡѹ�����㷨�ľ��
    BOOL bSuccess = CreateCompressor(
                    COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
                    NULL,                           //  Optional allocation routine
                    &hCompressor);                  //  Handle
    if (!bSuccess) {
        return FALSE;
    }

    // ������ѹ�������ݵĻ�����
    PBYTE pComPressDataBuf = new BYTE[m_PE->GetFileSize()];
    if (pComPressDataBuf == NULL) {
        return FALSE;
    }

    // ѹ������
    DWORD dwComDataSize = 0;
    bSuccess = Compress(
                hCompressor,
                m_PE->GetDosHeaderPointer(), // ��Ҫѹ�������ݵĻ�����
                m_PE->GetFileSize(),     // ��Ҫѹ�������ݵĴ�С
                pComPressDataBuf,        // ѹ��������ݵĻ�����
                m_PE->GetFileSize(),     // ѹ��������ݵĻ�������С
                &dwComDataSize);         // ѹ��������ݵĴ�С
    if (!bSuccess) {
        delete[] pComPressDataBuf;
        CloseCompressor(hCompressor);
        return FALSE;
    }

    // ����ѹ�����ݽ�
    m_dwCompressDataSize = CMyPe::GetAlignSize(dwComDataSize, m_PE->GetFileAlignment());
    m_pCompressData = new BYTE[m_dwCompressDataSize];
    if (m_pCompressData == NULL) {
        delete[] pComPressDataBuf;
        CloseCompressor(hCompressor);
        return FALSE;
    }

    ::RtlZeroMemory(m_pCompressData, m_dwCompressDataSize);
    MyMemCopy(m_pCompressData, pComPressDataBuf, dwComDataSize);

    // ������Դ
    delete[] pComPressDataBuf;
    CloseCompressor(hCompressor);
	return TRUE;
}

BOOL CPacker::GetShellCode() {
    m_pShellCode = new BYTE[0x100];
    ::RtlZeroMemory(m_pShellCode, 0x100);
    *m_pShellCode = 0xcc;
    m_dwShellCodeSize = CMyPe::GetAlignSize(1, m_PE->GetFileAlignment());
	return TRUE;
}

BOOL CPacker::RebuildSection() {
    ::RtlZeroMemory(&m_NewSecHdrs[0], sizeof(m_NewSecHdrs));

    // -û���ļ�ӳ��Ľ�
    MyMemCopy(m_NewSecHdrs[SHI_SPACE].Name, (LPVOID)".upx", MyStrLen(".upx"));
    m_NewSecHdrs[SHI_SPACE].VirtualAddress = CMyPe::GetAlignSize(m_PE->GetSizeOfHeaders(), m_PE->GetSectionAlignment());
    m_NewSecHdrs[SHI_SPACE].Misc.VirtualSize = m_PE->GetSizeOfImage() - m_NewSecHdrs[SHI_SPACE].VirtualAddress;
    m_NewSecHdrs[SHI_SPACE].PointerToRawData = m_PE->GetSizeOfHeaders();
    m_NewSecHdrs[SHI_SPACE].SizeOfRawData = 0;
    m_NewSecHdrs[SHI_SPACE].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // -�Ǵ����
    MyMemCopy(m_NewSecHdrs[SHI_CODE].Name, (LPVOID)".text", MyStrLen(".text"));
    m_NewSecHdrs[SHI_CODE].VirtualAddress = m_NewSecHdrs[SHI_SPACE].VirtualAddress + m_NewSecHdrs[SHI_SPACE].Misc.VirtualSize;
    m_NewSecHdrs[SHI_CODE].Misc.VirtualSize = CMyPe::GetAlignSize(m_dwShellCodeSize, m_PE->GetSectionAlignment());
    m_NewSecHdrs[SHI_CODE].PointerToRawData = m_NewSecHdrs[SHI_SPACE].PointerToRawData + m_NewSecHdrs[SHI_SPACE].SizeOfRawData;
    m_NewSecHdrs[SHI_CODE].SizeOfRawData = m_dwShellCodeSize;
    m_NewSecHdrs[SHI_CODE].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;


    // -��ѹ�����ݽ�
    MyMemCopy(m_NewSecHdrs[SHI_COM].Name, (LPVOID)".bss", MyStrLen(".bss"));
    m_NewSecHdrs[SHI_COM].VirtualAddress = m_NewSecHdrs[SHI_CODE].VirtualAddress + m_NewSecHdrs[SHI_CODE].Misc.VirtualSize;
    m_NewSecHdrs[SHI_COM].Misc.VirtualSize = CMyPe::GetAlignSize(m_dwCompressDataSize, m_PE->GetSectionAlignment());
    m_NewSecHdrs[SHI_COM].PointerToRawData = m_NewSecHdrs[SHI_CODE].PointerToRawData + m_NewSecHdrs[SHI_CODE].SizeOfRawData;
    m_NewSecHdrs[SHI_COM].SizeOfRawData = m_dwCompressDataSize;
    m_NewSecHdrs[SHI_COM].Characteristics = IMAGE_SCN_MEM_READ;

	return TRUE;
}

BOOL CPacker::RebuildPeHeader() {
    // ����ԭPEͷ
    m_dwNewPeHeaderSize = m_PE->GetSizeOfHeaders();
    m_pNewPeHeader = new BYTE[m_PE->GetSizeOfHeaders()];
    if (m_pNewPeHeader == NULL) {
        return FALSE;
    }
    ::RtlZeroMemory(m_pNewPeHeader, m_PE->GetSizeOfHeaders());
    MyMemCopy(m_pNewPeHeader, m_PE->GetDosHeaderPointer(), m_PE->GetSizeOfHeaders());

    //�޸�PEͷ
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)m_pNewPeHeader;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(m_pNewPeHeader + pDosHdr->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHdrs = (PIMAGE_SECTION_HEADER)((PBYTE)&pNtHdr->OptionalHeader +
                                     pNtHdr->FileHeader.SizeOfOptionalHeader);

    pNtHdr->FileHeader.NumberOfSections = SHI_COUT;
    pNtHdr->OptionalHeader.AddressOfEntryPoint = m_NewSecHdrs[SHI_CODE].VirtualAddress;
    pNtHdr->OptionalHeader.SizeOfImage = m_NewSecHdrs[SHI_COM].VirtualAddress + m_NewSecHdrs[SHI_COM].Misc.VirtualSize;

    //�����ڱ�
    MyMemCopy(pSecHdrs, m_NewSecHdrs, sizeof(m_NewSecHdrs));

    return TRUE;
}

BOOL CPacker::WritePackerFile(const char* pDstPath) {
    HANDLE hFile = CreateFile(pDstPath,           
                              GENERIC_WRITE,              
                              FILE_SHARE_READ,          
                              NULL,                    
                              CREATE_ALWAYS,            
                              FILE_ATTRIBUTE_NORMAL,     
                              NULL);                   
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD dwBytesToWrite = 0;
    //PEͷ
    if (!WriteFile(hFile, m_pNewPeHeader, m_dwNewPeHeaderSize, &dwBytesToWrite, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }

    //�Ǵ����
    if (!WriteFile(hFile, m_pShellCode, m_dwShellCodeSize, &dwBytesToWrite, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }

    //ѹ�����ݽ�
    if (!WriteFile(hFile, m_pCompressData, m_dwCompressDataSize, &dwBytesToWrite, NULL)) {
        CloseHandle(hFile);
        return FALSE;
    }

    //�ر��ļ�
    CloseHandle(hFile);

    // �ͷ���Դ
    if (m_pCompressData != NULL) {
        delete[] m_pCompressData;
        m_pCompressData = NULL;
    }
    if (m_pShellCode != NULL) {
        delete[] m_pShellCode;
        m_pShellCode = NULL;
    }
    if (m_pNewPeHeader != NULL) {
        delete[] m_pNewPeHeader;
        m_pNewPeHeader = NULL;
    }
    
    return TRUE;
}
