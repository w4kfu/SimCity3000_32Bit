#include "dbg.h"

FILE *fp = NULL;
int initialized = 0;

void open_file(void)
{
    if (!initialized)
    {
        fp = fopen(FILE_DBG, "w");
        initialized = 1;
    }
    else
        fp = fopen(FILE_DBG, "a");
}

void print_oep(DWORD dwOEP)
{
    open_file();
    fprintf(fp, "[+] OEP : %X\n", dwOEP);
    fclose(fp);
}

void print_size_new_iat(struct dll *ldll)
{
    struct api *lapi = NULL;
    DWORD   dwCountapi = 0;
    DWORD   dwCountdll = 0;
    DWORD   dwDLLNamesLength = 0;
    DWORD   dwAPINamesLength = 0;

    while (ldll)
    {
        lapi = ldll->pAPI;
        dwDLLNamesLength += strlen(ldll->pName) + 1;
        dwCountdll++;
        while (lapi)
        {
            dwCountapi++;
            dwAPINamesLength += strlen(lapi->pName) + 3;
            lapi = lapi->next;
        }
        ldll = ldll->next;
    }
    open_file();
    fprintf(fp, "[+] Number of DLL entry IAT : %d\n", dwCountdll);
    fprintf(fp, "[+] Number of API entry IAT : %d\n", dwCountapi);
    fprintf(fp, "[+] DLLNamesLength : %d\n", dwDLLNamesLength);
    fprintf(fp, "[+] APINamesLength : %d\n", dwAPINamesLength);
    fclose(fp);
}

void print_dll(struct dll *ldll)
{
    while (ldll)
    {
        open_file();
        fprintf(fp, "--------------------\n");
        fprintf(fp, "[+] Module Name : %s\n", ldll->pName);
        fprintf(fp, "[+] Module Base : %X\n", ldll->dwBase);
        fprintf(fp, "[+] Module SizeOfImage : %X\n", ldll->dwSizeOfImage);
        fprintf(fp, "\t API\n");
        print_api(ldll->pAPI);
        fprintf(fp, "--------------------\n");
        ldll = ldll->next;
        fclose(fp);
    }
}

void print_bug_api_found(char *pName, DWORD dwAddr, DWORD dwPAddress)
{
    open_file();
    fprintf(fp, "[-] BUG API : [%X] = %X ::: NAME = %s\n", dwAddr, dwPAddress, pName);
    fclose(fp);
}

void print_api(struct api *lapi)
{
    while (lapi)
    {
        fprintf(fp, "\t[+] Name : %s, Address : %X, Ordinal : %X\n", lapi->pName, lapi->dwAddress, lapi->wOrdinal);
        lapi = lapi->next;
    }
}

void hex_dump(void *data, int size)
{
	unsigned char *p =(unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};

    open_file();
    for(n = 1; n <= size; n++)
	{
        if (n % 16 == 1)
		{
            sprintf_s(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
        c = *p;
        if (isprint(c) == 0)
		{
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if (n % 16 == 0)
		{
            fprintf(fp, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
		else if (n % 8 == 0)
		{
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }

    if (strlen(hexstr) > 0)
	{
        fprintf(fp, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
    fclose(fp);
}
