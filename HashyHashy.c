#pragma once
#include <Windows.h>
#include <stdio.h>

#if !defined (Get16Bits)
#define Get16Bits(d) ((((UINT32)(((const UINT8*)(d))[1])) << 8)\
                       +(UINT32)(((const UINT8*)(d))[0]) )
#endif

SIZE_T StringLengthA(LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

UINT32 HashStringSuperFastHashA(PCHAR String)
{
	INT Length = StringLengthA(String);
	UINT32 Hash = Length;
	INT Tmp = 0;

	INT Rem = Length & 3;
	Length >>= 2;

	for (; Length > 0; Length--)
	{
		Hash += Get16Bits(String);
		Tmp = (Get16Bits(String + 2) << 11) ^ Hash;
		Hash = (Hash << 16) ^ Tmp;
#pragma warning( push )
#pragma warning( disable : 6305)
		String += 2 * sizeof(UINT16);
#pragma warning( pop ) 
		Hash += Hash >> 11;
	}

	switch (Rem)
	{
	case 3:
	{
		Hash += Get16Bits(String);
		Hash ^= Hash << 16;
		Hash ^= ((UCHAR)String[sizeof(UINT16)]) << 18;
		Hash += Hash >> 11;
		break;
	}
	case 2:
	{
		Hash += Get16Bits(String);
		Hash ^= Hash << 11;
		Hash ^= Hash >> 17;
		break;
	}
	case 1:
	{
		Hash += (UCHAR)*String;
		Hash ^= Hash << 10;
		Hash += Hash >> 1;
	}
	}

	Hash ^= Hash << 3;
	Hash += Hash >> 5;
	Hash ^= Hash << 4;
	Hash += Hash >> 17;
	Hash ^= Hash << 25;
	Hash += Hash >> 6;

	return Hash;
}

LPVOID getFunctionAddressByHash(LPCSTR library, UINT32 hash)
{
	LPVOID functionAddress = NULL;
	// Get base address of the module in which our exported function of interest resides (kernel32 in the case of CreateThread)
	HMODULE libraryBase = LoadLibraryA(library);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Get RVAs to exported function related information
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	// Iterate through exported functions, calculate their hashes and check if any of them match our hash of 0x00544e304 (CreateThread)
	// If yes, get its virtual memory address (this is where CreateThread function resides in memory of our process)
	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		// Calculate hash for this exported function
		DWORD functionNameHash = HashStringSuperFastHashA(functionName);

		// If hash for CreateThread is found, resolve the function address
		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			functionAddress = (LPVOID)((DWORD_PTR)libraryBase + functionAddressRVA);
			//TODO: Remove printF
			//printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
			return functionAddress;
		}

	}
}