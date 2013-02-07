#ifndef HOOK_STUFF_H_
#define HOOK_STUFF_H_

#include <windows.h>
#include <stddef.h>

#define LDE_X86 0

#ifdef __cplusplus
extern "C"
#endif
int __stdcall LDE(void* address , DWORD type);

void	setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr);
void    setup_Hook_WriteProcessMemory(void);

#endif // HOOK_STUFF_H_
