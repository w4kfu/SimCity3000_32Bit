#ifndef __PESTUFF_H__
#define __PESTUFF_H__

#include <windows.h>

DWORD GetTextAddress(HMODULE hModule);
DWORD FindCode(const LPSTR pSig, const DWORD dwSize, const DWORD dwAddress, const DWORD dwLength);
DWORD GetTextSize(HMODULE hModule);

#endif // __PESTUFF_H__
