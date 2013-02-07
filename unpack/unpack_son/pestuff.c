#include "pestuff.h"

DWORD GetTextAddress(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pHeader;
    unsigned int i;


    pDos = (PIMAGE_DOS_HEADER)hModule;
    pNT = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
    pHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNT + sizeof(IMAGE_NT_HEADERS));
    for (i = 0; i < pNT->FileHeader.NumberOfSections; ++i)
    {
        if (pHeader->Characteristics && IMAGE_SCN_CNT_CODE)
        {
            return ((DWORD)hModule + pHeader->VirtualAddress);
        }
        ++pHeader;
    }
    return 0;
}

DWORD FindCode(const LPSTR pSig, const DWORD dwSize, const DWORD dwAddress, const DWORD dwLength)
{
    DWORD i;

    for (i = dwAddress; i < (dwAddress + dwLength); ++i)
        if (memcmp((LPVOID)i, pSig, dwSize) == 0)
            return i;
    return 0;
}

DWORD GetTextSize(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    PIMAGE_SECTION_HEADER pHeader;
    unsigned int i;


    pDos = (PIMAGE_DOS_HEADER)hModule;
    pNT = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
    pHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNT + sizeof(IMAGE_NT_HEADERS));
    for (i = 0; i < pNT->FileHeader.NumberOfSections; ++i)
    {
        if (pHeader->Characteristics && IMAGE_SCN_CNT_CODE)
        {
            return (pHeader->SizeOfRawData > pHeader->Misc.VirtualSize ? pHeader->Misc.VirtualSize : pHeader->SizeOfRawData);
        }
        ++pHeader;
    }
    return 0;
}
