#include "hook_stuff.h"

BOOL WINAPI DllMain(HANDLE hDLL, DWORD dwReason, LPVOID lpReserved)
{
    DisableThreadLibraryCalls(GetModuleHandleA("unpack_father.dll"));
    setup_Hook_WriteProcessMemory();
	return TRUE;
}
