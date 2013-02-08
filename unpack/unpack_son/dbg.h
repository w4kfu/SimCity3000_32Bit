#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "fixIAT.h"

#define FILE_DBG "dbg_msg_son.txt"

enum TYPE_INSTRU
{
    CALL = 0x15,
    JUMP = 0x25
};

void print_oep(DWORD dwOEP);
void print_size_new_iat(struct dll *ldll);
void print_dll(struct dll *ldll);
void print_bug_api_found(char *pName, DWORD dwAddr, DWORD dwPAddress);
void print_api(struct api *lapi);
void hex_dump(void *data, int size);
void print_call_jmp(DWORD dwAddrText, DWORD dwDestAddress, DWORD dwPAddress, enum TYPE_INSTRU t, struct dll *dll);
void print_iat_info(DWORD dwStart, DWORD dwEnd);
void print_bug_dll_found(DWORD dwAddr, DWORD dwPAddress);
void print_info_redirect(DWORD dwKernTxt, DWORD dwKernSize);
void print_res(DWORD dwResolve);

#endif // __DBG_H__
