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

void print_write_proc(DWORD dwAddr, HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
    open_file();
    fprintf(fp, "[+] WriteProcessMemory(Handle = 0x%X, lpBaseAddress = 0x%X, lpBuffer = 0x%X, nSize = 0x%X, lpNumberOfBytesWritten = 0x%X) : %X\n", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten, dwAddr);
    fclose(fp);
    hex_dump(lpBuffer, nSize);
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
            /* store address for this line */
            sprintf_s(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
        c = *p;
        if (isalnum(c) == 0)
		{
            c = '.';
        }
        /* store hex str (for left side) */
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if (n % 16 == 0)
		{
            /* line completed */
            fprintf(fp, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
		else if (n % 8 == 0)
		{
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0)
	{
        /* print rest of buffer if not empty */
        fprintf(fp, "[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
    fclose(fp);}
