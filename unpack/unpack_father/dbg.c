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
    hex_dump((void*)lpBuffer, nSize);
}

void print_create_proc(DWORD dwAddr, LPCWSTR lpApplicationName, LPWSTR lpCommandLine)
{
    open_file();
    fprintf(fp, "[+] CreateProcessW(lpApplicationName = %s, lpCommandLine = %s) : %X\n", lpApplicationName, lpCommandLine, dwAddr);
    fclose(fp);
}

void hex_dump(void *data, size_t size)
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
        if (isalnum(c) == 0)
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
