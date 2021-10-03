#pragma once
#include <windows.h>
SIZE_T StringLengthA(LPCSTR String);
UINT32 HashStringSuperFastHashA(PCHAR String);
LPVOID getFunctionAddressByHash(char* library, UINT32 hash);