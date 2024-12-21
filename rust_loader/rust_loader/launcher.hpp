#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>

namespace launcher
{
	using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
	using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
	using f_EXE_ENTRY_POINT = INT(WINAPI*)();

	struct MANUAL_MAPPING_DATA
	{
		f_LoadLibraryA pLoadLibraryA;
		f_GetProcAddress pGetProcAddress;

		BYTE* pbase;
		HINSTANCE hMod;
	};

	HANDLE LaunchHostProcess(std::string host_proc);
	bool ManualMapExe(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader = false, bool ClearNonNeededSections = true, bool AdjustProtections = true);
	void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
}