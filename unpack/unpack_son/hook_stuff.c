#include "hook_stuff.h"

extern PVOID protVectoredHandler;
extern DWORD OriginalEP;
DWORD dwOldProtect;

void (__stdcall *Resume_BaseProcessStart)(void) = NULL;

void __declspec (naked) Hook_BaseProcessStart(void)
{
    __asm
    {
        pushad
        mov OriginalEP, eax
    }
    print_oep(OriginalEP);
    protVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandler);
    VirtualProtect((LPVOID)OriginalEP, 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &dwOldProtect);
    __asm
    {
        popad
        jmp Resume_BaseProcessStart
    }
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

void setup_Hook_RtlUserThreadStart(void)
{
    // Use the same trampo as in WinXP
	Resume_BaseProcessStart = (DWORD(__stdcall *)(void))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_BaseProcessStart, 0x90, 0x1000);
    setup_hook("ntdll.dll", "RtlUserThreadStart", &Hook_BaseProcessStart, Resume_BaseProcessStart, 0);
}

void setup_Hook_BaseProcessStart(void)
{
    LPSTR pSig = "\x33\xED\x50\x6A\x00\xE9";
    DWORD BaseProcessStartThunk = 0;


    BaseProcessStartThunk = FindCode(pSig, sizeof(pSig),
                                    GetTextAddress(GetModuleHandleA("kernel32.dll")),
                                    GetTextSize(GetModuleHandleA("kernel32.dll")));
    if (BaseProcessStartThunk == 0)
    {
        MessageBoxA(NULL, "BaseThreadStart() not found", "ERROR", 0);
        return;
    }

	Resume_BaseProcessStart = (DWORD(__stdcall *)(void))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_BaseProcessStart, 0x90, 0x1000);
	setup_hook(0, 0, &Hook_BaseProcessStart, Resume_BaseProcessStart, BaseProcessStartThunk);
}
