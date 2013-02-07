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
