#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define FILE_DBG "dbg_msg_father.txt"

void print_write_proc(DWORD dwAddr, HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
void hex_dump(void *data, int size);

#endif // __DBG_H__
