#pragma once
#include <windows.h>

HANDLE CreateShellCodeThread(PVOID shellcode, SIZE_T bufferSize, HANDLE procHandle);
VOID XORData(PCHAR shellcode, PCHAR key, SIZE_T bufferSize);
VOID ChangeMemProtection(PVOID baseAddr, SIZE_T bufferSize, DWORD protection);
LPVOID getHashedFunctionPointer(LPCSTR lib, LPCSTR funcName);