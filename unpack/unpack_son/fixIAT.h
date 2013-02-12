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

struct rdata_s
{
	struct	rdata_s *next;
	DWORD	rdata_addr;
	DWORD	txt_addr;
};

struct redir_api
{
	struct redir_api *next;
	DWORD api_addr;
	struct	rdata_s	*rdata;
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

// ALL REDIR STUFF

struct redir_api *add_redir_api(struct redir_api *ap, DWORD api_addr, DWORD rdata_addr, DWORD txt_addr);
struct rdata_s *add_rdata(struct rdata_s *rd, DWORD rdata_addr, DWORD txt_addr);
struct rdata_s *get_rdata(struct rdata_s *rd, DWORD *rdata_addr);

void fix_api_rdata(struct redir_api *ap);
void reorder_api_rdata(struct redir_api *ap);

struct redir_api *find_redir_api(struct redir_api *ap, DWORD api_addr);
struct rdata_s *find_rdata(struct rdata_s *rd, DWORD rdata_addr);
struct rdata_s *find_txt(struct rdata_s *rd, DWORD txt_addr);

// DBG
DWORD Countnbrdata(struct redir_api *ap);
DWORD Countnbapi(struct redir_api *ap);

#define OneByteLength 00
#define TwoByteLength 01
#define FourByteLength 3
#define BreakOnExec 0
#define BreakOnWrite 1
#define BreakOnAccess 3
#define GlobalFlag 2
#define LocalFlag 1

#define DR7flag(_size,_type,flag,HBPnum) (((_size<<2 | _type)<< (HBPnum*4 +16)) | (flag << (HBPnum*2)))

#define BREAKPOINT_LOCAL_EXACT      0x00000300
#define DR0_BREAKPOINT_LOCAL      0x00000001
#define DR0_ACCESS               0x00030000
#define DR0_FOUR_BYTE            0x000C0000


#endif // __FIXIAT_H__

