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

BOOL SetPrivilege(
                          HANDLE hToken,  // access token handle
                          LPCTSTR lpszPrivilege,    // name of privilege to enable/disable
                          BOOL bEnablePrivilege    // to enable (or disable privilege)
                          )
{
      // Token privilege structure
      TOKEN_PRIVILEGES tp;
      // Used by local system to identify the privilege
      LUID luid;

      if(!LookupPrivilegeValueA(
            NULL,                   // lookup privilege on local system
            lpszPrivilege,          // privilege to lookup
            &luid))                       // receives LUID of privilege
      {
          MessageBoxA(NULL, "LookupPrivilegeValue()", "ERROR", 0);
            //wprintf(L"LookupPrivilegeValue() failed, error: %u\n", GetLastError());
            return FALSE;
      }
            //wprintf(L"LookupPrivilegeValue() - \"%s\" found!\n", lpszPrivilege);

      // Number of privilege
      tp.PrivilegeCount = 1;
      // Assign luid to the 1st count
      tp.Privileges[0].Luid = luid;

      // Enable/disable
      if(bEnablePrivilege)
      {
            // Enable
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            //wprintf(L"\"%s\" was enabled!\n", lpszPrivilege);
      }
      else
      {
            // Disable
            tp.Privileges[0].Attributes = 0;
            //wprintf(L"\"%s\" was disabled!\n", lpszPrivilege);
      }

      // Adjusting the new privilege
      if(!AdjustTokenPrivileges(
            hToken,
            FALSE,      // If TRUE, function disables all privileges,
                        // if FALSE the function modifies privilege based on the tp
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES) NULL,
            (PDWORD) NULL))
      {
          MessageBoxA(NULL, "AdjustTokenPrivileges()", "ERROR", 0);
            //wprintf(L"AdjustTokenPrivileges() failed to adjust the new privilege, error: %u\n", GetLastError());
            return FALSE;
      }
      return TRUE;
}

BOOL IsRealBadReadPtr(void* address, int size)
{
    MEMORY_BASIC_INFORMATION mbi;

    if ((DWORD)address & 0x80000000)
        return TRUE;

    VirtualQuery(address,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
    if ((address >= mbi.BaseAddress) &&
    ((int)address + size <= (int)mbi.BaseAddress + (int)mbi.RegionSize) &&
    (mbi.State == MEM_COMMIT) &&
    ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE)) != 0))
        return FALSE;
    else
        return TRUE;
}

void* ParsePE(BYTE* hMod, DWORD dwChamp)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pPE;
    IMAGE_DATA_DIRECTORY* rvas;
    DWORD nmbOfRva;

    if (pDosHeader->e_magic != 'ZM')
        return (void*)NULL;
    pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE *)hMod);
    if (pPE->Signature != 'EP')
        return (void*)NULL;

    pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE *)hMod);
    nmbOfRva = pPE->OptionalHeader.NumberOfRvaAndSizes;
    rvas = (IMAGE_DATA_DIRECTORY *) &pPE->OptionalHeader.DataDirectory;
    switch(dwChamp)
    {
        case EXPORT_TABLE:
            if (nmbOfRva >= 1)
                return (void*)(rvas[0].VirtualAddress);
            else
                return (void*)NULL;
        case EXPORT_TABLE_SIZE:
            if (nmbOfRva >= 1)
                return (void*)(rvas[0].Size);
            else
                return (void*)NULL;
    }
    return (void*)NULL;
}

void* ParseSection(PIMAGE_SECTION_HEADER pSection, DWORD dwChamp)
{
    switch (dwChamp)
    {
        case SEC_NAME:
            return (void*)pSection->Name;
        case SEC_VIRT_SIZE:
            return (void*)pSection->Misc.VirtualSize;
        case SEC_VIRT_ADDR:
            return (void*)pSection->VirtualAddress;
        case SEC_RAW_SIZE:
            return (void*)pSection->SizeOfRawData;
        case SEC_RAW_ADDR:
            return (void*)pSection->PointerToRawData;
        case SEC_CHARAC:
            return (void*)pSection->Characteristics;
    }
    return NULL;
}

void* GetSectionInfo(BYTE* hMod, char *name, DWORD dwChamp)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSections;
    int nbSection, i;

    pPE = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE *)pDosHeader);
    nbSection = pPE->FileHeader.NumberOfSections;

    for (i = 0; i < nbSection; i++)
    {
        pSections = (PIMAGE_SECTION_HEADER)((BYTE *)pPE + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i);
        if (!strcmp(pSections->Name, name))
            return ParseSection(pSections, dwChamp);
    }
    return 0;
}
