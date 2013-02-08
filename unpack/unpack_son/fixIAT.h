#ifndef __FIXIAT_H__
#define __FIXIAT_H__

#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include "pestuff.h"
#include "hook_stuff.h"

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


#define OneByteLength 00
#define TwoByteLength 01
#define FourByteLength 3
#define BreakOnExec 0
#define BreakOnWrite 1
#define BreakOnAccess 3
#define GlobalFlag 2
#define LocalFlag 1

#define DR7flag(_size,_type,flag,HBPnum) (((_size<<2 | _type)<< (HBPnum*4 +16)) | (flag << (HBPnum*2)))













#endif // __FIXIAT_H__

