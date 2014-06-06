#pragma once
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <dbghelp.h>

#define MAX_MODULES 512

typedef struct _PF_MAPFILE
{
	HANDLE hFile;
	HANDLE hMap;
	LPVOID hMapViewOfFile;
	PMINIDUMP_MEMORY64_LIST pDir;
}PF_MAPFILE, *PPF_MAPFILE;

typedef struct _PF_FOUND_INFO
{
	ULONG64	address;
	PBYTE	ptrFile;
}PF_FOUND_INFO, *PPF_FOUND_INFO;

typedef struct _CV_INFO_PDB70
{
	DWORD      CvSignature;
	GUID       Signature;       // unique identifier 
	DWORD      Age;             // an always-incrementing value 
	BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
}CV_INFO_PDB70, *PCV_INFO_PDB70;

typedef struct _PF_MODULE_INFOS
{
	ULONG64 BaseOfImage;
	ULONG32 SizeOfImage;
	PCV_INFO_PDB70 InfosPDB70;
	wchar_t pdbFilePath[MAX_PATH];
}PF_MODULE_INFOS, *PPF_MODULE_INFOS;

PPF_MODULE_INFOS PF_GetModuleInfos(LPCWSTR szModuleName, PPF_MODULE_INFOS pModulesInfos);
bool PF_InitMemoryStreamList(PPF_MAPFILE pMapFile);
bool PF_GetModulesInformations(PPF_MAPFILE pMapFile, PPF_MODULE_INFOS pModulesInfos);
bool PF_InitMiniDump(PPF_MAPFILE pMapFile, LPCWSTR szFileName);
void PF_ReleaseMiniDumpMemoryList(PPF_MAPFILE pMapFile);