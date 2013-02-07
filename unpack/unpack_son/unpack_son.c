#include "hook_stuff.h"

BOOL WINAPI DllMain(HANDLE hDLL, DWORD dwReason, LPVOID lpReserved)
{
    OSVERSIONINFOA lpVersionInfo = {0};

    DisableThreadLibraryCalls(GetModuleHandleA("unpack_son.dll"));
    lpVersionInfo.dwOSVersionInfoSize = sizeof(lpVersionInfo);
    if (GetVersionExA(&lpVersionInfo) != 0)
    {
        if (lpVersionInfo.dwMajorVersion >= 6)
        {
            /* not yet implemented */
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
