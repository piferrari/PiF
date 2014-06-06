#include "stdafx.h"
#include "Memory.h"
#include "Symbols.h"

PBYTE PF_FindAddressInMemory(PPF_MAPFILE pMapFile, ULONG64 Source, ULONG64 Length)
{
	bool found = FALSE;
	// ajuste le pointeur de fichier
	PBYTE ptr = (PBYTE)(pMapFile->hMapViewOfFile) + pMapFile->pDir->BaseRva;

	ULONG64 nMemory64;
	PMINIDUMP_MEMORY_DESCRIPTOR64 memory64;
	ULONG64 offsetToRead = 0;

	// parcours toutes les plages de mémoires (00000000`001000000 ... 0000000`004d0000 ou encore 000007fe`fd38c830) à la rechercher de l'adresse à lire exemple 4d0000
	for (nMemory64 = 0; nMemory64 < pMapFile->pDir->NumberOfMemoryRanges; nMemory64++, /* Ajuste le pointeur à chaque tour --> */ ptr += memory64->DataSize)
	{
		memory64 = &(pMapFile->pDir->MemoryRanges[nMemory64]);
		if (((ULONG64)Source >= memory64->StartOfMemoryRange) && ((ULONG64)Source + Length < (memory64->StartOfMemoryRange + memory64->DataSize)))
		{
			/* Calcul le delta entre le début de la plage mémoire et l'endroit où se trouve la valeur à lire */
			offsetToRead = (ULONG64)Source - memory64->StartOfMemoryRange;
			found = TRUE;
			break;
		}
	}
	if (found)
	{
		// ajuste le pointeur de fichier
		return ptr + offsetToRead;
	}
	else
	{
		return NULL;
	}
}

ULONG64 PF_FindAddressInMemoryForSymbol(wchar_t *szModuleSymbol, PPF_MODULE_INFOS pModulesInfos)
{
	wchar_t *ptr = wcschr(szModuleSymbol, L'!');
	
	int size = (ptr - szModuleSymbol) + 1;
	wchar_t *module = new wchar_t[size];
	wcsncpy_s(module, size, szModuleSymbol, (ptr - szModuleSymbol));

	PPF_MODULE_INFOS mi = PF_GetModuleInfos(module, pModulesInfos);

	IDiaSymbol *global = PF_OpenAndFindGlobalScopeFromPdbFile((LPTSTR)mi->pdbFilePath);

	delete[] module;

	if (global)
	{
		wchar_t *symbol = ++ptr;
		ULONG64 offset = PF_GetVirtualAddressOffsetForSymbolName(global, symbol);
		if (offset == NULL)
		{
			fwprintf_s(stdout, L"Could not find symbol\n");
			return 0;
		}
		
		offset = mi->BaseOfImage + offset;
		return offset;
	}
	return 0;
}