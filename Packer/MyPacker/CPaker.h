#pragma once

#include <windows.h>
#include "CMyPe.h"
#include "MyLibC.h"

class CPaker {
public:
    CPaker();
    ~CPaker();

public:
    BOOL Pack(const char* pSrcPath, const char* pDstPath);

private:
    // PE数据解析
    CMyPe* m_PE;

private:
    // 压缩操作相关
    BOOL  DoCompress();
    PBYTE m_pCompressDataBuff;  // 压缩数据的内存地址
    DWORD m_dwComDataAlignSize; // 压缩数据与文件对齐值对齐后大小
    DWORD m_dwComDataSize;      // 压缩数据的真实大小

private:
    // 壳代码相关
    BOOL  GetShellCode();
    PBYTE m_pShellCodeBuff;  // 壳代码的内存地址
    DWORD m_dwShellCodeSize; // 壳代码与文件对齐值对齐后大小

private:
    // 构造新的节表
    BOOL RebuildSection();
    enum SecHdrIdx { 
        SHI_SPACE, 
        SHI_CODE, 
        SHI_COM, 
        SHI_COUT 
    };
    IMAGE_SECTION_HEADER m_NewSecHdrs[SHI_COUT];  // 新的节表

    // 构造新的PE头
    BOOL  RebuildPeHeader();
    PBYTE m_pNewPeHeader;      // PE—Header的内存地址
    DWORD m_dwNewPeHeaderSize; // PE—Header与文件对齐值对齐后大小

private:
    // 写入新的PE到磁盘
    BOOL WritePackerFile(const char* pDstPath);
};

