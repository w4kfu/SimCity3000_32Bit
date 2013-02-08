#include "hook_stuff.h"
#include "fixIAT.h"

PVOID protVectoredHandler;
DWORD OriginalEP;

void    fixthisshit(PIMAGE_DOS_HEADER pDosHeader, DWORD dwOEP)
{
    PBYTE   dwActual;
    PDWORD  pAddress;
    DWORD   dwNearIAT;
    DWORD   dwStartIAT;
    DWORD   dwEndIAT;
    DWORD   dwSizeIAT = 0;
    struct dll *NewDLL = NULL;

    init_fixIAT();

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
