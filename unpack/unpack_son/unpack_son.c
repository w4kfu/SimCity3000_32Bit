#include "hook_stuff.h"

BOOL WINAPI DllMain(HANDLE hDLL, DWORD dwReason, LPVOID lpReserved)
{
    DisableThreadLibraryCalls(GetModuleHandleA("unpack_son.dll"));
    //setup_Hook_WriteProcessMemory();
    MessageBoxA(NULL, "IN DA SON", "SON", 0);
	return TRUE;
}
