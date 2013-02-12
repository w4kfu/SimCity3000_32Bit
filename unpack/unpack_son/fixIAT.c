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
                ExceptionInfo->ContextRecord->Esp += 4;
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL TestRedirVersion(DWORD dwPAddress)
{
    DWORD dwLen = 0;

    dwLen = LDE((void*)(dwPAddress), LDE_X86);   // PUSH NUM
    if (dwLen == 5)
    {
        if (*(BYTE*)(dwPAddress + 5) == 0x9C)   // PUSHFD
        {
            dwLen = LDE((void*)(dwPAddress + 5), LDE_X86);
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

LONG CALLBACK ProtectionFaultVectoredHandlerPushad(PEXCEPTION_POINTERS ExceptionInfo)
{
    DWORD dwOldProtect;
    DWORD dwLenInstru;
    DWORD address;
    DWORD eip;
    static BOOL stepInto = FALSE;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        address = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        eip = ExceptionInfo->ContextRecord->Eip;

        if (eip == address && *(BYTE*)eip == 0x54) // PUSH ESP
        {
            ExceptionInfo->ContextRecord->Dr0 = ExceptionInfo->ContextRecord->Esp;
            // clean this global var
            HBEsp = ExceptionInfo->ContextRecord->Dr0;
            ExceptionInfo->ContextRecord->Dr7 = DR7flag(FourByteLength, BreakOnAccess, GlobalFlag | LocalFlag, 0);
        }
        else
        {
            stepInto = TRUE;
            ExceptionInfo->ContextRecord->EFlags |= 0x100;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if ((ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) && (stepInto))
    {
        eip = ExceptionInfo->ContextRecord->Eip;
        dwLenInstru = LDE((void*)(eip), LDE_X86);
        VirtualProtect((LPVOID)(eip + dwLenInstru), 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect);
        stepInto = FALSE;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {

        address = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        if (address == HBEsp)
        {
            ExceptionInfo->ContextRecord->Dr0 = 0;
            ExceptionInfo->ContextRecord->Dr7 = 0;
            ExceptionInfo->ContextRecord->Esp += 4;
            ResolvAPI = *(DWORD*)(ExceptionInfo->ContextRecord->Esp);
            ExceptionInfo->ContextRecord->Esp += 4;
            *(DWORD*)(ExceptionInfo->ContextRecord->Esp) = *(DWORD*)(ExceptionInfo->ContextRecord->Esp + 8);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void SetupBreakOnpushad(DWORD dwAddr, DWORD dwPAddress)
{
    PVOID pVectoredHandler;
    DWORD dwOldProtect;

    pVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandlerPushad);
    // *(dwPAddress + 7) : 0x54 ; PUSH ESP
    VirtualProtect((LPVOID)(dwPAddress + 7), 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect);
    __asm
    {
        pushad
        pushfd
        call    dwAddr
        popfd
        popad
    }
    RemoveVectoredExceptionHandler(pVectoredHandler);
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

    Context.Dr0 = Context.Esp - 0x34;
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
    RemoveVectoredExceptionHandler(pVectoredHandler);
    Context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &Context);
    Context.Dr0 = 0;
    Context.Dr7 = 0;
    SetThreadContext(hThread, &Context);
    print_res(ResolvAPI);
}

void fixRedirect(DWORD dwAddr, DWORD dwPAddress)
{
    /*DWORD dwKernTXT = 0;
    DWORD dwKernSize = 0;
    DWORD dwUserTXT = 0;
    DWORD dwUserSize = 0;*/

    /*dwKernTXT = (DWORD)GetSectionInfo(GetModuleHandle("kernel32.dll"), ".text", SEC_VIRT_ADDR) + GetModuleHandle("kernel32.dll");
    dwKernSize = (DWORD)GetSectionInfo(GetModuleHandle("kernel32.dll"), ".text", SEC_VIRT_SIZE);
    dwUserTXT = (DWORD)GetSectionInfo(GetModuleHandle("user32.dll"), ".text", SEC_VIRT_ADDR) + GetModuleHandle("user32.dll");
    dwUserSize = (DWORD)GetSectionInfo(GetModuleHandle("user32.dll"), ".text", SEC_VIRT_SIZE);*/

    if (TestRedirVersion(dwPAddress) == TRUE)
    {
        //SetEspTrick(dwAddr);
        SetupBreakOnpushad(dwAddr, dwPAddress);
    }
    else
    {
        MessageBoxA(NULL, "Redir Not Supported", "ERROR", 0);
    }

}

struct redir_api *FixRedir(struct redir_api *ap, DWORD dwAddr)
{
    DWORD   dwOdlProt;
    DWORD   dwTextBase = 0;
    DWORD   dwTextSize = 0;
    DWORD   i;
    BYTE    *ptr;
    DWORD   val;

    print_bug_dll_found(dwAddr, *(DWORD*)dwAddr);

    dwTextBase = (DWORD)GetSectionInfo((BYTE*)GetModuleHandle(0), ".text", SEC_VIRT_ADDR) + (DWORD)GetModuleHandle(0);
    dwTextSize = (DWORD)GetSectionInfo((BYTE*)GetModuleHandle(0), ".text", SEC_VIRT_SIZE);
    for (i = 0; i < dwTextSize; i++)
    {
        ptr = (BYTE*)(dwTextBase + i);
        if ((*ptr == 0xFF && *(ptr + 1) == 0x15) //|| // call []
            //(*ptr == 0xFF && *(ptr + 1) == 0x25) //|| // jmp [] // JMP require a random pushed value
            //(*ptr == 0x8B && *(ptr + 1) == 0x35) || // mov esi, ...
            //(*ptr == 0x8B && *(ptr + 1) == 0x2D) || // mov ebp, ...
            //(*ptr == 0x8B && *(ptr + 1) == 0x1D) || // mov ebx, ...
            //(*ptr == 0x8B && *(ptr + 1) == 0x3D))   // mov edi, ...
            )
            {
                val = *(ptr + 5) << 0x18 | *(ptr + 4) << 0x10 | *(ptr + 3) << 0x8  | *(ptr + 2);
                if (val == dwAddr)
                {
                    //fixRedirect(dwAddr, *(PVOID*)dwAddr);
                    fixRedirect((DWORD)ptr, *(DWORD*)dwAddr);
                    ap = add_redir_api(ap, ResolvAPI, val, (DWORD)(ptr + 2));
                }
            }
        else if ((*ptr == 0xFF && *(ptr + 1) == 0x25)) //|| // jmp [] // JMP require a random pushed value
            //(*ptr == 0x8B && *(ptr + 1) == 0x35) || // mov esi, ...
            //(*ptr == 0x8B && *(ptr + 1) == 0x2D) || // mov ebp, ...
            //(*ptr == 0x8B && *(ptr + 1) == 0x1D) || // mov ebx, ...
            //(*ptr == 0x8B && *(ptr + 1) == 0x3D))
            {
                val = *(ptr + 5) << 0x18 | *(ptr + 4) << 0x10 | *(ptr + 3) << 0x8  | *(ptr + 2);
                if (val == dwAddr)
                {

                }
            }
    }
    return ap;
    //VirtualProtect(dwAddr, 4, 0x40, &dwOdlProt);
    //*(DWORD*)dwAddr = ResolvAPI;

    //ap = add_api(ap, ResolvAPI, val, (DWORD)(ptr + 2), 0);
}

void fixiat(DWORD dwStartIAT, DWORD dwEndIAT, struct dll **NewDLL)
{
    DWORD dwAddr;
    struct dll *NewDLLIAT = NULL;
    struct dll *AcutalDLLIAT = NULL;
    struct dll *actualDLL = NULL;
    struct api *actualAPI = NULL;
	struct redir_api *ap = NULL;

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
                ap = FixRedir(ap, dwAddr);
                //print_redir_api(ap);
                //MessageBoxA(0, "DA FUCK", "CANT FIND A FUCKING DLL ?", 0);
            }
        }
    }
    // DBG
    print_dll(NewDLLIAT);
    print_size_new_iat(NewDLLIAT);
    *NewDLL = NewDLLIAT;

	print_redir_api(ap);
	reorder_api_rdata(ap);
	print_after();
    print_redir_api(ap);
    fix_api_rdata(ap);
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

struct redir_api *find_redir_api(struct redir_api *ap, DWORD api_addr)
{
	while (ap)
	{
		if (ap->api_addr == api_addr)
			return ap;
		ap = ap->next;
	}
	return NULL;
}

struct rdata_s *find_rdata(struct rdata_s *rd, DWORD rdata_addr)
{
	while (rd)
	{
		if (rd->rdata_addr == rdata_addr)
			return rd;
		rd = rd->next;
	}
	return NULL;
}

struct rdata_s *find_txt(struct rdata_s *rd, DWORD txt_addr)
{
	while (rd)
	{
		if (rd->txt_addr == txt_addr)
			return rd;
		rd = rd->next;
	}
	return NULL;
}


struct redir_api *add_redir_api(struct redir_api *ap, DWORD api_addr, DWORD rdata_addr, DWORD txt_addr)
{
	struct redir_api *new_ap = NULL;
	struct redir_api *cur = NULL;

	if (ap)
	{
		if ((cur = find_redir_api(ap, api_addr)) != NULL)
		{
			cur->rdata = add_rdata(cur->rdata, rdata_addr, txt_addr);
			return ap;
		}
	}
	new_ap = (struct redir_api*)malloc(sizeof (struct redir_api));
	memset(new_ap, 0, sizeof (struct redir_api));
	new_ap->next = ap;
	new_ap->api_addr = api_addr;
	new_ap->rdata = add_rdata(new_ap->rdata, rdata_addr, txt_addr);
	return new_ap;
}

struct rdata_s *add_rdata(struct rdata_s *rd, DWORD rdata_addr, DWORD txt_addr)
{
	struct rdata_s *new_rdata = NULL;

	new_rdata = (struct rdata_s*)malloc(sizeof (struct rdata_s));
	memset(new_rdata, 0, sizeof (struct rdata_s));
	new_rdata->next = rd;
	new_rdata->rdata_addr = rdata_addr;
	new_rdata->txt_addr = txt_addr;
    return new_rdata;
}

struct rdata_s *get_rdata(struct rdata_s *rd, DWORD *rdata_addr)
{
	struct rdata_s *rd_actual;

	if (rd)
	{
		*rdata_addr = rd->rdata_addr;
		rd_actual = rd;
		rd = rd->next;
		free(rd_actual);
		return rd;
	}
	return NULL;
}

DWORD Lenrdata(struct rdata_s *rd)
{
    DWORD dwCount = 0;

	while (rd)
	{
	    dwCount++;
		rd = rd->next;
	}
	return dwCount;
}

// FREE ALL THIS SHIT ?
DWORD Countnbrdata(struct redir_api *ap)
{
    struct rdata_s *rdata_used = NULL;
    struct rdata_s *rdata_actual = NULL;
    DWORD dwCount = 0;

    while (ap)
    {
        rdata_actual = ap->rdata;
        while (rdata_actual)
        {
            if (find_rdata(rdata_used, rdata_actual->rdata_addr) == NULL)
                rdata_used = add_rdata(rdata_used, rdata_actual->rdata_addr, 0);
            rdata_actual = rdata_actual->next;
        }
        ap = ap->next;
    }
    while (rdata_used)
    {
        dwCount++;
        rdata_used = rdata_used->next;
    }
    return dwCount;
}

DWORD Countnbapi(struct redir_api *ap)
{
    DWORD dwCount = 0;

    while (ap)
    {
        dwCount++;
        ap = ap->next;
    }
    return dwCount;
}

DWORD find_free(struct redir_api *ap, struct rdata_s *rdata_used, DWORD actual_rdata_addr)
{
    struct rdata_s *rdata_actual = NULL;
    struct rdata_s *rd = NULL;

    while (ap)
    {
        rdata_actual =  ap->rdata;

        if (find_rdata(rdata_actual, actual_rdata_addr) == NULL)
        {
            if (Lenrdata(rdata_actual) > 1)
            {
                while (rdata_actual)
                {
                    if (find_rdata(rdata_used, rdata_actual->rdata_addr) == NULL)
                        return rdata_actual->rdata_addr;
                    rdata_actual = rdata_actual->next;
                }
            }
        }
        ap = ap->next;
    }
    return 0;
}

void reorder_api_rdata(struct redir_api *ap)
{
	struct rdata_s *rdata_free = NULL;
	struct rdata_s *rdata_used = NULL;
	struct rdata_s *rdata_actual = NULL;
	DWORD actual_rdata_addr = 0;
    struct redir_api *save_ap = NULL;
    DWORD nb_ap = 0;
    DWORD save_api = 0;
    struct rdata_s *save_rdata = NULL;
    DWORD next_free_rdata;

    printnb(ap);
    save_ap = ap;
	while (ap)
	{
		if (ap->rdata == NULL)
		{
			MessageBoxA(NULL, "There is something wrong!", "!?", 0);
			exit(0);
		}
		save_api = 0; // BOOL
		actual_rdata_addr = ap->rdata->rdata_addr;
		if (find_rdata(rdata_used, actual_rdata_addr))
		{
			if (rdata_free == NULL)
			{
			    //save_rdata = add_rdata(save_rdata, actual_rdata_addr, ap->rdata->txt_addr);
			    //ap = ap->next;
			    //continue;
			    // Search actual_rdata_addr in other place
                next_free_rdata = find_free(save_ap, rdata_used, actual_rdata_addr);
                //print_free_bug(next_free_rdata, actual_rdata_addr);
                if (next_free_rdata == 0)
                {
                    MessageBoxA(NULL, "WTF no more entry", "!?", 0);
                    exit(0);
                }
			    rdata_free = add_rdata(rdata_free, next_free_rdata, ap->rdata->txt_addr);
			    //print_free_bug(actual_rdata_addr, nb_ap);
			    //print_redir_api(save_ap);
				//MessageBoxA(NULL, "FIX IT", "!?", 0);
				//exit(0);
                nb_ap++;
			}
            rdata_free = get_rdata(rdata_free, &actual_rdata_addr);
		}
        rdata_used = add_rdata(rdata_used, actual_rdata_addr, ap->rdata->txt_addr);
        rdata_actual = ap->rdata;
        while (rdata_actual)
        {
            if (rdata_actual->rdata_addr != actual_rdata_addr)
            {
                if (find_rdata(rdata_used, actual_rdata_addr) == NULL)
                    rdata_free = add_rdata(rdata_free, rdata_actual->rdata_addr, rdata_actual->txt_addr);
                rdata_actual->rdata_addr = actual_rdata_addr;
            }
            rdata_actual = rdata_actual->next;
        }
		ap = ap->next;
	}
	print_free_rdata(rdata_free, nb_ap);
}

void fix_api_rdata(struct redir_api *ap)
{
	DWORD OldProtect;
	struct rdata_s *rdata_actual = NULL;

	while (ap)
	{
		rdata_actual = ap->rdata;
		VirtualProtect((LPVOID)rdata_actual->rdata_addr, 4, PAGE_EXECUTE_READWRITE, &OldProtect);
		*(DWORD*)rdata_actual->rdata_addr = ap->api_addr;
		VirtualProtect((LPVOID)rdata_actual->rdata_addr, 4, OldProtect, &OldProtect);
		while (rdata_actual)
		{
            VirtualProtect((LPVOID)rdata_actual->txt_addr, 4, PAGE_EXECUTE_READWRITE, &OldProtect);
            *(DWORD*)rdata_actual->txt_addr = rdata_actual->rdata_addr;
            VirtualProtect((LPVOID)rdata_actual->txt_addr, 4, OldProtect, &OldProtect);
			rdata_actual = rdata_actual->next;
		}
		ap = ap->next;
	}
}
