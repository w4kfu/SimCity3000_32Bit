#include "hook_stuff.h"

BOOL (__stdcall *Resume_WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) = NULL;

BOOL __stdcall Hook_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    DWORD	return_addr;
	DWORD	Addr;
	HANDLE	hThread;
	HMODULE	hKernel32;

	__asm
	{
		mov eax, [ebp + 4]
		mov return_addr, eax
	}
	print_write_proc(return_addr, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    /*
    DBG STUFF ;)
	*((BYTE*)lpBuffer + 0x73) = 0xEB;
	*((BYTE*)lpBuffer + 0x74) = 0xFE;
	*/

	hKernel32 = GetModuleHandleA("kernel32.dll");
	Addr = (DWORD)VirtualAllocEx(hProcess, 0, strlen(DLL_NAME),
					MEM_COMMIT, PAGE_READWRITE);
	if (Addr == 0)
	{
		MessageBoxA(NULL, "VirtualAllocEx failed()", "Error", 0);
	}
	Resume_WriteProcessMemory(hProcess, (LPVOID)Addr, (void*)DLL_NAME, strlen(DLL_NAME), NULL);
	hThread = CreateRemoteThread(hProcess, NULL, 0,
					(LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32,"LoadLibraryA"),
					(LPVOID)Addr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
    return (Resume_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten));
}

void	setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr)
{
	DWORD	OldProtect;
	DWORD	len;
	FARPROC	Proc;

	if (addr != 0)
	{
		Proc = (FARPROC)addr;
	}
	else
	{
		Proc = GetProcAddress(GetModuleHandleA(module), name_export);
		if (!Proc)
		    return;
	}
	len = 0;
	while (len < 5)
		len += LDE((BYTE*)Proc + len , LDE_X86);
	memcpy(trampo, Proc, len);
	*(BYTE *)((BYTE*)trampo + len) = 0xE9;
	*(DWORD *)((BYTE*)trampo + len + 1) = (BYTE*)Proc - (BYTE*)trampo - 5;
	VirtualProtect(Proc, len, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD*)((char*)Proc + 1) = (BYTE*)Hook_func - (BYTE*)Proc - 5;
	VirtualProtect(Proc, len, OldProtect, &OldProtect);
}

void setup_Hook_WriteProcessMemory(void)
{
	Resume_WriteProcessMemory = (BOOL(__stdcall *)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_WriteProcessMemory, 0x90, 0x1000);
	setup_hook("kernel32.dll", "WriteProcessMemory", &Hook_WriteProcessMemory, Resume_WriteProcessMemory, 0);
}
