#ifndef __FIXIAT_H__
#define __FIXIAT_H__

#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "pestuff.h"

struct dll
{
    char *pName;
    DWORD dwBase;
    DWORD dwSizeOfImage;
    struct api *pAPI;
    struct dll *next;
};

struct api
{
    char *pName;
    DWORD dwAddress;
    WORD wOrdinal;
    struct api *next;
};

void init_fixIAT(void);
void add_api_to_module(struct dll *ldd);
DWORD getendIAT(DWORD dwNearIAT);
DWORD getstartIAT(DWORD dwNearIAT);
void fixiat(DWORD dwStartIAT, DWORD dwEndIAT, struct dll **NewDLL);
PBYTE Reconstruct(DWORD dwStartIAT, struct dll *NewDLLIAT, DWORD dwVAIAT);
DWORD count_nb_dll(struct dll *ldll);
DWORD computeSizeIAT(struct dll *NewDLLIAT);

struct dll *add_dll(struct dll *ldll, char *name, DWORD dwBase, DWORD dwSizeOfImage);
struct api *add_api(struct api *lapi, char *name, DWORD dwAddress, WORD wOrdinal);

struct dll *find_dll(struct dll *ldll, DWORD dwAddr);
struct api *find_api(struct api *lapi, DWORD dwAddr);

#endif // __FIXIAT_H__

