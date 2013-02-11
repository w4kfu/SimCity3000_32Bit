#include "hook_stuff.h"
#include "fixIAT.h"

PVOID protVectoredHandler;
DWORD OriginalEP;
LPCTSTR lpszPrivilege = "SeSecurityPrivilege";
BOOL bEnablePrivilege = TRUE;
HANDLE hToken;

void    fixthisshit(PIMAGE_DOS_HEADER pDosHeader, DWORD dwOEP)
{
    PBYTE   dwActual;
    PDWORD  pAddress;
    DWORD   dwNearIAT;
    DWORD   dwStartIAT;
    DWORD   dwEndIAT;
    DWORD   dwSizeIAT = 0;
    DWORD   dwTextBase = 0;
    DWORD   dwTextSize = 0;
    struct dll *NewDLL = NULL;

    RemoveVectoredExceptionHandler(protVectoredHandler);

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (SetPrivilege(hToken, lpszPrivilege, bEnablePrivilege) == FALSE)
    {
        MessageBoxA(NULL, "SetPrivilege() failed", "ERROR", 0);
    }

    dwTextBase = (DWORD)GetSectionInfo((BYTE*)pDosHeader, ".text", SEC_VIRT_ADDR) + (DWORD)pDosHeader;
    dwTextSize = (DWORD)GetSectionInfo((BYTE*)pDosHeader, ".text", SEC_VIRT_SIZE);
    init_fixIAT();
    for (dwActual = dwOEP; dwActual < dwTextBase + dwTextSize - 5; dwActual++)
    {
        if ((dwActual[0] == 0xFF) && ((dwActual[1] == 0x25)  || (dwActual[1] == 0x15)))
        {
            pAddress = *(PDWORD*)(dwActual + 2);
            if ((!IsRealBadReadPtr(pAddress, 4)) && (!IsRealBadReadPtr((void*)*pAddress, 4)))
            {
                DWORD address = *pAddress;
                dwNearIAT = pAddress;
                print_call_jmp(dwActual, pAddress, address, dwActual[1], NULL);
                break;
            }
        }
    }

    dwStartIAT = getstartIAT(pAddress);
    dwEndIAT = getendIAT(pAddress);
    print_iat_info(dwStartIAT, dwEndIAT);
    fixiat(dwStartIAT, dwEndIAT, &NewDLL);
}

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    DWORD oldProtect;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {
        DWORD address = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
        DWORD eip = ExceptionInfo->ContextRecord->Eip;

        if ((eip == OriginalEP))
        {
            MessageBoxA(0, "Fuck Yeah !", "OEP Found",0);
            fixthisshit(GetModuleHandle(0), eip);
            MessageBoxA(0, "KILL DA PROCESSS !", "KILL THEM ALL",0);
            TerminateProcess(GetCurrentProcess(), 0);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL WINAPI DllMain(HANDLE hDLL, DWORD dwReason, LPVOID lpReserved)
{
    OSVERSIONINFOA lpVersionInfo = {0};

    DisableThreadLibraryCalls(GetModuleHandleA("unpack_son.dll"));
    lpVersionInfo.dwOSVersionInfoSize = sizeof(lpVersionInfo);
    if (GetVersionExA(&lpVersionInfo) != 0)
    {
        if (lpVersionInfo.dwMajorVersion >= 6)
        {
            setup_Hook_RtlUserThreadStart();
        }
        else
        {
            setup_Hook_BaseProcessStart();
        }
    }
    else
    {
        MessageBoxA(NULL, "Unable to retrieve operating system version", "ERROR", 0);
    }
	return TRUE;
}
