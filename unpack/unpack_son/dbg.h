#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "fixIAT.h"

#define FILE_DBG "dbg_msg_son.txt"

void print_oep(DWORD dwOEP);
void print_size_new_iat(struct dll *ldll);
void print_dll(struct dll *ldll);
void print_bug_api_found(char *pName, DWORD dwAddr, DWORD dwPAddress);
void print_api(struct api *lapi);
void hex_dump(void *data, int size);

#endif // __DBG_H__
