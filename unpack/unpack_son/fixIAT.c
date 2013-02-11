#include "fixIAT.h"

struct dll *list_dll = NULL;
static int NbHBRead = 0;
extern PVOID protVectoredHandler;
DWORD ResolvAPI = 0;
DWORD HBEsp = 0;

void init_fixIAT(void)
{
    MODULEENTRY32 mod;
    HANDLE TH32S;
    struct dll *cur_dll = NULL;

    TH32S = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, GetCurrentProcessId());
    mod.dwSize = sizeof (MODULEENTRY32);
    Module32First(TH32S, &mod);
    list_dll = add_dll(list_dll, mod.szModule, (DWORD)mod.modBaseAddr, mod.modBaseSize);
    while (Module32Next(TH32S, &mod))
            list_dll = add_dll(list_dll, mod.szModule, (DWORD)mod.modBaseAddr, mod.modBaseSize);
    CloseHandle(TH32S);
    cur_dll = list_dll;
    while (cur_dll)
    {
        add_api_to_module(cur_dll);
        cur_dll = cur_dll->next;
    }
    // DBG
    print_dll(list_dll);
}

void add_api_to_module(struct dll *ldd)
{
    PIMAGE_EXPORT_DIRECTORY pExportTable;
    DWORD dwOffsetExportTable;
    DWORD dwSizeOfExportTable;
    DWORD dwNbNames;
    DWORD dwNbExports;
    DWORD dwIndex;
    DWORD dwBaseAddress;
    WORD wOrdinal;

    dwOffsetExportTable = (DWORD)ParsePE((BYTE*)ldd->dwBase, EXPORT_TABLE);
    if (dwOffsetExportTable == 0)
        return;
    dwSizeOfExportTable = (DWORD)ParsePE((BYTE*)ldd->dwBase, EXPORT_TABLE_SIZE);
    if (dwSizeOfExportTable == 0)
        return;
    pExportTable = (PIMAGE_EXPORT_DIRECTORY)(dwOffsetExportTable + ldd->dwBase);
    dwNbNames = pExportTable->NumberOfNames;
    dwNbExports = pExportTable->NumberOfFunctions;
    dwBaseAddress = ldd->dwBase;
    for (dwIndex = 0 ; dwIndex < dwNbNames; dwIndex++)
    {
        wOrdinal = ((WORD *)(pExportTable->AddressOfNameOrdinals + dwBaseAddress))[dwIndex];
        ldd->pAPI = add_api(ldd->pAPI,
                             (char *)(((DWORD *)(pExportTable->AddressOfNames + dwBaseAddress))[dwIndex] + dwBaseAddress),
                            ((DWORD *)(pExportTable->AddressOfFunctions + dwBaseAddress))[wOrdinal] + dwBaseAddress,
                            wOrdinal);
    }
}

char *to_lower(char *name)
{
    char *str = strdup(name);
    DWORD i;

    for(i = 0; str[i] != '\0'; i++)
    {
        if (str[i] >= 'A' && str[i] <= 'Z')
            str[i] = (str[i]-'A') + 'a';
    }
    return str;
}

struct dll *add_dll(struct dll *ldll, char *name, DWORD dwBase, DWORD dwSizeOfImage)
{
	struct dll *new_dll = NULL;
	struct dll *cur_dll = NULL;

    new_dll = (struct dll*)malloc(sizeof (struct dll));
    if (!new_dll)
        return NULL;
    new_dll->pName = to_lower(name);
    new_dll->dwBase = dwBase;
    new_dll->dwSizeOfImage = dwSizeOfImage;
    new_dll->pAPI = NULL;
    new_dll->next = NULL;
    if (ldll == NULL)
    {
        return new_dll;
    }
    else
    {
        cur_dll = ldll;
        while (cur_dll->next)
            cur_dll = cur_dll->next;
        cur_dll->next = new_dll;
    }
    return ldll;
}

struct api *add_api(struct api *lapi, char *name, DWORD dwAddress, WORD wOrdinal)
{
    struct api *new_api = NULL;
	struct api *cur_api = NULL;

    new_api = (struct api*)malloc(sizeof (struct api));
    if (!new_api)
        return NULL;
    new_api->pName = strdup(name);
    new_api->dwAddress = dwAddress;
    new_api->wOrdinal = wOrdinal;
    new_api->next = NULL;
    if (lapi == NULL)
    {
         return new_api;
    }
    else
    {
        cur_api = lapi;
        while (cur_api->next)
            cur_api = cur_api->next;
        cur_api->next = new_api;
    }
    return lapi;
}


struct dll *find_dll(struct dll *ldll, DWORD dwAddr)
{
    while (ldll)
    {
        if ((dwAddr >= ldll->dwBase) && (dwAddr <= (ldll->dwBase + ldll->dwSizeOfImage)))
            return ldll;
        ldll = ldll->next;
    }
    return NULL;
}

struct api *find_api(struct api *lapi, DWORD dwAddr)
{
    while (lapi)
    {
        if (lapi->dwAddress == dwAddr)
            return lapi;
        lapi = lapi->next;
    }
    return NULL;
}


DWORD   getstartIAT(DWORD dwNearIAT)
{
    DWORD   dwCount = 0;

    while (1)
    {
        // IAT START ?
        if (dwCount == 2)
            break;
        dwNearIAT -= 4;
        if (!IsRealBadReadPtr((void*)dwNearIAT, 4))
        {
            if (IsRealBadReadPtr(*(PVOID*)dwNearIAT, 4)) // 0 or whatever ?
            {
                dwCount++;
                continue;
            }
            dwCount = 0;
        }
        else
            break;
    }
    return (dwNearIAT + 8);
}

DWORD getendIAT(DWORD dwNearIAT)
{
    DWORD   dwCount = 0;

    while (1)
    {
        // IAT END ?
        if (dwCount == 2)
            break;
        dwNearIAT += 4;
        if (!IsRealBadReadPtr((void*)dwNearIAT, 4))
        {
            if (IsRealBadReadPtr(*(PVOID*)dwNearIAT, 4)) // 0 or whatever ?
            {
                dwCount++;
                continue;
            }
            dwCount = 0;
        }
        else
            break;
    }
    return (dwNearIAT - 8);
}

void fixNtdllToKernel(struct api *actualAPI)
{
    if (!strcmp(actualAPI->pName, "RtlRestoreLastWin32Error"))
    {
        strcpy(actualAPI->pName, "SetLastError");
        actualAPI->wOrdinal = 0x2c2;
    }
    if (!strcmp(actualAPI->pName, "RtlGetLastWin32Error"))
    {
        strcpy(actualAPI->pName, "GetLastError");
        actualAPI->wOrdinal = 0x169;
    }
    if (!strcmp(actualAPI->pName, "RtlDeleteCriticalSection"))
    {
        strcpy(actualAPI->pName, "DeleteCriticalSection");
        actualAPI->wOrdinal = 0x80;
    }
    if (!strcmp(actualAPI->pName, "RtlAllocateHeap"))
    {
        strcpy(actualAPI->pName, "HeapAlloc");
        actualAPI->wOrdinal = 0x206;
    }
    if (!strcmp(actualAPI->pName, "RtlEnterCriticalSection"))
    {
        strcpy(actualAPI->pName, "EnterCriticalSection");
        actualAPI->wOrdinal = 0x097;
    }
    if (!strcmp(actualAPI->pName, "RtlLeaveCriticalSection"))
    {
        strcpy(actualAPI->pName, "LeaveCriticalSection");
        actualAPI->wOrdinal = 0x244;
    }
    if (!strcmp(actualAPI->pName, "RtlFreeHeap"))
    {
        strcpy(actualAPI->pName, "HeapFree");
        actualAPI->wOrdinal = 0x20C;
    }
    if (!strcmp(actualAPI->pName, "RtlInitializeCriticalSection"))
    {
        strcpy(actualAPI->pName, "InitializeCriticalSection");
        actualAPI->wOrdinal = 0x2E6;
    }
    if (!strcmp(actualAPI->pName, "RtlExitUserThread"))
    {
        strcpy(actualAPI->pName, "ExitThread");
        actualAPI->wOrdinal = 0x11D;
    }
    if (!strcmp(actualAPI->pName, "NtdllDefWindowProc_A"))
    {
        strcpy(actualAPI->pName, "DefWindowProcA");
        actualAPI->wOrdinal = 0x680;
    }
}

LONG CALLBACK ProtectionFaultVectoredHandlerRedir(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        DWORD address = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        DWORD eip = ExceptionInfo->ContextRecord->Eip;

        if (address == HBEsp)
        {
            NbHBRead++;
            if (NbHBRead == 2)
            {
                ExceptionInfo->ContextRecord->Esp += 4;
                ResolvAPI = *(DWORD*)(ExceptionInfo->ContextRecord->Esp);
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL TestRedirVersion(DWORD dwPAddress)
{
    DWORD dwLen = 0;

    dwLen = LDE(dwPAddress, LDE_X86);   // PUSH NUM
    if (dwLen == 5)
    {
        if (*(BYTE*)(dwPAddress + 5) == 0x9C)   // PUSHFD
        {
            dwLen = LDE(dwPAddress + 5, LDE_X86);
            if (dwLen == 1)
            {
                if (*(BYTE*)(dwPAddress + 6) == 0x60)   // PUSHAD
                {
                    return TRUE;
                }
            }
        }

    }
    return 0;
}

void SetEspTrick(DWORD dwPAddress)
{
    CONTEXT Context;
    DWORD addrHBP;
    HANDLE hThread;
    PVOID pVectoredHandler;

    NbHBRead = 0;
    pVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandlerRedir);
    hThread = GetCurrentThread();
    Context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &Context);
    Context.Dr0 = Context.Esp - 0x30;
    HBEsp = Context.Dr0;
    Context.Dr7 = DR7flag(FourByteLength, BreakOnAccess, GlobalFlag | LocalFlag, 0);
    SetThreadContext(hThread, &Context);
    __asm
    {
        pushad
        pushfd
        call    dwPAddress
        popfd
        popad
    }
    Context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &Context);
    Context.Dr0 = 0;
    Context.Dr7 = 0;
    SetThreadContext(hThread, &Context);
    RemoveVectoredExceptionHandler(pVectoredHandler);
    print_res(ResolvAPI);
}

void fixRedirect(DWORD dwAddr, DWORD dwPAddress)
{
    DWORD dwKernTXT = 0;
    DWORD dwKernSize = 0;
    DWORD dwUserTXT = 0;
    DWORD dwUserSize = 0;

    dwKernTXT = (DWORD)GetSectionInfo(GetModuleHandle("kernel32.dll"), ".text", SEC_VIRT_ADDR) + GetModuleHandle("kernel32.dll");
    dwKernSize = (DWORD)GetSectionInfo(GetModuleHandle("kernel32.dll"), ".text", SEC_VIRT_SIZE);
    dwUserTXT = (DWORD)GetSectionInfo(GetModuleHandle("user32.dll"), ".text", SEC_VIRT_ADDR) + GetModuleHandle("user32.dll");
    dwUserSize = (DWORD)GetSectionInfo(GetModuleHandle("user32.dll"), ".text", SEC_VIRT_SIZE);

    if (TestRedirVersion(dwPAddress) == TRUE)
    {
        SetEspTrick(dwPAddress);
    }
    else
    {
        MessageBoxA(NULL, "Redir Not Supported", "ERROR", 0);
    }

}

void fixiat(DWORD dwStartIAT, DWORD dwEndIAT, struct dll **NewDLL)
{
    DWORD dwAddr;
    struct dll *NewDLLIAT = NULL;
    struct dll *AcutalDLLIAT = NULL;
    struct dll *actualDLL = NULL;
    struct api *actualAPI = NULL;

    for (dwAddr = dwStartIAT; dwAddr <= dwEndIAT; dwAddr += 4)
    {
        if (!IsRealBadReadPtr((void*)dwAddr, 4) && !IsRealBadReadPtr(*(PVOID*)dwAddr, 4))
        {
            actualDLL = find_dll(list_dll, *(PVOID*)dwAddr);
            if (actualDLL)
            {
                actualAPI = find_api(actualDLL->pAPI, *(PVOID*)dwAddr);
                if (!actualAPI)
                {
                    print_bug_api_found(actualDLL->pName, dwAddr, *(PVOID*)dwAddr);
                    MessageBoxA(0, "DA FUCK", "CANT FIND THIS FUCKING API ?", 0);
                }
                // New DLL entry already created ?
                if (strcmp(actualDLL->pName, "ntdll.dll"))
                {
                    if (!(AcutalDLLIAT = find_dll(NewDLLIAT, *(PVOID*)dwAddr)))
                    {
                        NewDLLIAT = add_dll(NewDLLIAT, actualDLL->pName, actualDLL->dwBase, actualDLL->dwSizeOfImage);
                        AcutalDLLIAT = find_dll(NewDLLIAT, *(PVOID*)dwAddr);
                    }
                }
                fixNtdllToKernel(actualAPI);
                AcutalDLLIAT->pAPI = add_api(AcutalDLLIAT->pAPI, actualAPI->pName, actualAPI->dwAddress, actualAPI->wOrdinal);
            }
            else
            {
                DWORD dwOdlProt;

                print_bug_dll_found(dwAddr, *(PVOID*)dwAddr);
                fixRedirect(dwAddr, *(PVOID*)dwAddr);
                VirtualProtect(dwAddr, 4, 0x40, &dwOdlProt);
                *(DWORD*)dwAddr = ResolvAPI;
                //MessageBoxA(0, "DA FUCK", "CANT FIND A FUCKING DLL ?", 0);
            }
        }
    }
    // DBG
    print_dll(NewDLLIAT);
    print_size_new_iat(NewDLLIAT);
    *NewDLL = NewDLLIAT;
}

DWORD count_nb_dll(struct dll *ldll)
{
    DWORD dwCount = 0;

    while (ldll)
    {
        dwCount += 1;
        ldll = ldll->next;
    }
    return dwCount;
}

DWORD computeSizeIAT(struct dll *NewDLLIAT)
{
    struct api *lapi = NULL;
    DWORD   dwCountdll = 0;
    DWORD   dwDLLNamesLength = 0;
    DWORD   dwAPINamesLength = 0;

    while (NewDLLIAT)
    {
        lapi = NewDLLIAT->pAPI;
        dwDLLNamesLength += strlen(NewDLLIAT->pName) + 1;
        dwCountdll++;
        while (lapi)
        {
            dwAPINamesLength += strlen(lapi->pName) + 3; // + 1 + sizeof (WORD)
            lapi = lapi->next;
        }
        NewDLLIAT = NewDLLIAT->next;
    }
    return (dwDLLNamesLength + dwAPINamesLength + (dwCountdll + 1) * sizeof (IMAGE_IMPORT_DESCRIPTOR));
}

PBYTE Reconstruct(DWORD dwStartIAT, struct dll *NewDLLIAT, DWORD dwVAIAT)
{
    char *newIAT = NULL;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    struct api *actualAPI = NULL;
    DWORD   dwCountEntry = 0;
    DWORD   dwBase = (DWORD)GetModuleHandle(NULL);
    char    *name = NULL;
    DWORD   SizeIAT;
    DWORD   Name = 0;
    DWORD   dwOldProtect;
    PBYTE   pAddr = NULL;

    SizeIAT = computeSizeIAT(NewDLLIAT);
    newIAT = malloc(SizeIAT);
    memset(newIAT, 0, SizeIAT);
    ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)newIAT;
    name = newIAT + (sizeof (IMAGE_IMPORT_DESCRIPTOR) * (count_nb_dll(NewDLLIAT) + 1));
    Name = dwVAIAT + (sizeof (IMAGE_IMPORT_DESCRIPTOR) * (count_nb_dll(NewDLLIAT) + 1));
    while (NewDLLIAT)
    {
        ImportDescriptor->Name = Name;
        ImportDescriptor->OriginalFirstThunk = 0;
        ImportDescriptor->TimeDateStamp = 0;
        ImportDescriptor->ForwarderChain = 0;
        ImportDescriptor->FirstThunk = dwStartIAT - dwBase;

        memcpy(name, NewDLLIAT->pName, strlen(NewDLLIAT->pName));
        name += strlen(NewDLLIAT->pName) + 1;
        Name += strlen(NewDLLIAT->pName) + 1;

        actualAPI = NewDLLIAT->pAPI;
        while (actualAPI)
        {
            VirtualProtect((PVOID)dwStartIAT, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
            *(DWORD*)dwStartIAT = Name;
            actualAPI->wOrdinal += 1;
            memcpy(name, &actualAPI->wOrdinal, 2);
            name += 2;
            Name += 2;
            memcpy(name, actualAPI->pName, strlen(actualAPI->pName));

            name += strlen(actualAPI->pName) + 1;
            Name += strlen(actualAPI->pName) + 1;
            dwStartIAT += 4;
            actualAPI = actualAPI->next;
        }
        ImportDescriptor += 1;
        dwCountEntry += 1;
        dwStartIAT += 4;
        NewDLLIAT = NewDLLIAT->next;
    }
    hex_dump(newIAT, SizeIAT);
    return newIAT;
}
