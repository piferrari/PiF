#include "stdafx.h"
#include "Minidump.h"

PPF_MODULE_INFOS PF_GetModuleInfos(LPCWSTR szModuleName, PPF_MODULE_INFOS pModulesInfos)
{
	if (pModulesInfos == NULL) return NULL;
	if (wcslen(szModuleName) < 1) return NULL;

	int maxLen = wcslen(szModuleName) + wcslen(L".pdb") + 1;
	wchar_t *moduleName = new wchar_t[maxLen];

	if (moduleName)
	{
		memset(moduleName, L'\0', maxLen);
		wcsncat_s(moduleName, maxLen, szModuleName, wcslen(szModuleName));
		wcsncat_s(moduleName, maxLen, L".pdb", wcslen(L".pdb"));

		for (int i = 0; i < MAX_MODULES; i++)
		{
			if ((PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName != "" && (PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName != NULL)
			{
				size_t size = strlen((PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName) + 1;
				wchar_t * wcsModuleName = new wchar_t[size];
				if (wcsModuleName == NULL)
				{
					return NULL;
				}

				size_t convertedChars = 0;
				mbstowcs_s(&convertedChars, wcsModuleName, size, (PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName, _TRUNCATE);

				if (wcscmp(moduleName, wcsModuleName) == 0)
				{
					delete[] wcsModuleName;
					return &pModulesInfos[i];
				}
				if (wcsModuleName)
					delete[] wcsModuleName;
			}
		}
		delete[] moduleName;
	}
	else
	{
		return NULL;
	}
	return NULL;
}

bool PF_InitMemoryStreamList(PPF_MAPFILE pMapFile)
{
	PMINIDUMP_DIRECTORY StreamDirectory;
	PVOID StreamPointer;
	ULONG StreamSize;
	// Remplit la structure MINIDUMP_DIRECTORY pour Memory64ListStream
	if (!MiniDumpReadDumpStream(pMapFile->hMapViewOfFile, Memory64ListStream, &StreamDirectory, &StreamPointer, &StreamSize))
	{
		return FALSE;
	}

	// pointe sur la liste des mémoires (toutes .data .text etc. soit 00000000`004d0000 ou encore 000007fe`fd38c830) en ajoutant l'offset fichier (RVA)
	pMapFile->pDir = (PMINIDUMP_MEMORY64_LIST)((PBYTE)(pMapFile->hMapViewOfFile) + StreamDirectory->Location.Rva);
	return TRUE;
}

bool PF_GetModulesInformations(PPF_MAPFILE pMapFile, PPF_MODULE_INFOS pModulesInfos)
{
	PMINIDUMP_DIRECTORY StreamDirectory;
	PVOID StreamPointer;
	ULONG StreamSize;
	const HANDLE fakeProcess = (HANDLE)1;

	SymInitialize(fakeProcess, NULL, FALSE);
	SymSetOptions(SYMOPT_DEBUG);
	SymSetSearchPath(fakeProcess, "SRV*c:\\pfsymbols*http://msdl.microsoft.com/download/symbols");

	if (!MiniDumpReadDumpStream(pMapFile->hMapViewOfFile, ModuleListStream, &StreamDirectory, &StreamPointer, &StreamSize))
	{
		return FALSE;
	}

	for (ULONG i = 0; i < ((PMINIDUMP_MODULE_LIST)StreamPointer)->NumberOfModules && i < MAX_MODULES; i++)
	{
		pModulesInfos[i].BaseOfImage = (ULONG64)((PMINIDUMP_MODULE_LIST)StreamPointer)->Modules[i].BaseOfImage;
		pModulesInfos[i].SizeOfImage = ((PMINIDUMP_MODULE_LIST)StreamPointer)->Modules[i].SizeOfImage;

		pModulesInfos[i].InfosPDB70  = (PCV_INFO_PDB70)((PBYTE)(pMapFile->hMapViewOfFile) + ((PMINIDUMP_MODULE_LIST)StreamPointer)->Modules[i].CvRecord.Rva);

		PMINIDUMP_STRING pMinidumpString = (PMINIDUMP_STRING)((PBYTE)(pMapFile->hMapViewOfFile) + ((PMINIDUMP_MODULE_LIST)StreamPointer)->Modules[i].ModuleNameRva);

		/* Les deux seuls fichiers pdb qui nous intéresse */
		if (strcmp((PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName, "wdigest.pdb") == 0 ||
			strcmp((PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName, "lsasrv.pdb") == 0)
		{
			char filePath[MAX_PATH] = {};
			DWORD three = 0;
			DWORD flags = SSRVOPT_GUIDPTR;
			if (SymFindFileInPath(fakeProcess, NULL, (PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName, &pModulesInfos[i].InfosPDB70->Signature, pModulesInfos[i].InfosPDB70->Age, three,
				flags, filePath, NULL, NULL))
			{
				wprintf(L"Found symbol file for %S.\n", (PCSTR)pModulesInfos[i].InfosPDB70->PdbFileName);
				size_t size = strlen(filePath) + 1;
				size_t convertedChars = 0;
				mbstowcs_s(&convertedChars, pModulesInfos[i].pdbFilePath, size, filePath, _TRUNCATE);
			}
			else
			{
				LPTSTR errorText = NULL;
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
					NULL,
					GetLastError(),
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
					(LPTSTR)&errorText,
					0,
					NULL);

				if (NULL != errorText)
				{
					wprintf(L"%s\n", errorText);
					LocalFree(errorText);
					errorText = NULL;
				}
				return FALSE;
			}
		}
		else
		{
			pModulesInfos[i].pdbFilePath[0] = '\0';
		}
	}
	SymCleanup(fakeProcess);

	return TRUE;
}

bool PF_InitMiniDump(PPF_MAPFILE pMapFile, LPCWSTR szFileName)
{
	pMapFile->hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (pMapFile->hFile == INVALID_HANDLE_VALUE) return FALSE;

	pMapFile->hMap = CreateFileMapping(pMapFile->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!pMapFile->hMap) return FALSE;

	DWORD dwFileSize = GetFileSize(pMapFile->hFile, NULL);

	pMapFile->hMapViewOfFile = (LPVOID)MapViewOfFile(pMapFile->hMap, FILE_MAP_READ, 0, 0, dwFileSize);
	if (!pMapFile->hMapViewOfFile) return FALSE;

	return TRUE;
}

void PF_ReleaseMiniDumpMemoryList(PPF_MAPFILE pMapFile)
{
	if (pMapFile->hMapViewOfFile) UnmapViewOfFile(pMapFile->hMapViewOfFile);
	if (pMapFile->hMap) CloseHandle(pMapFile->hMap);
	if (pMapFile->hFile) CloseHandle(pMapFile->hFile);
}