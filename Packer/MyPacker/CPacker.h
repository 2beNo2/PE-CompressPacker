#pragma once

#include <windows.h>
#include "CPe.h"
#include "MyLibC.h"

class CPacker {
public:
    CPacker();
    ~CPacker();

public:
    BOOL Pack(const char* pSrcPath, const char* pDstPath);

private:
    // PE���ݽ������
    CPe* m_PE;

private:
    // ѹ���������
    BOOL  DoCompressData();
    PBYTE m_pCompressData;      // ѹ�����ݵ��ڴ��ַ
    DWORD m_dwComDataAlignSize; // ѹ���������ļ�����ֵ������С
    DWORD m_dwComDataSize;      // ѹ�����ݵ���ʵ��С

private:
    // �Ǵ������
    BOOL  GetShellCode();
    PBYTE m_pShellCode;      // �Ǵ�����ڴ��ַ
    DWORD m_dwShellCodeSize; // �Ǵ������ļ�����ֵ������С

private:
    // �����µĽڱ�
    BOOL RebuildSection();
    enum SecHdrIdx { 
        SHI_SPACE, 
        SHI_CODE, 
        SHI_COM, 
        SHI_COUT 
    };
    IMAGE_SECTION_HEADER m_NewSecHdrs[SHI_COUT];  // �µĽڱ�

    // �����µ�PEͷ
    BOOL  RebuildPeHeader();
    PBYTE m_pNewPeHeader;      // PE��Header���ڴ��ַ
    DWORD m_dwNewPeHeaderSize; // PE��Header���ļ�����ֵ������С

private:
    // д���µ�PE������
    BOOL WritePackerFile(const char* pDstPath);
};

