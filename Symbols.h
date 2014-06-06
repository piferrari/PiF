#pragma once
#include <windows.h>
#include <atlbase.h>
#include <dia2.h>

IDiaSymbol* PF_OpenAndFindGlobalScopeFromPdbFile(const wchar_t *szFilename);
ULONG64 PF_GetVirtualAddressOffsetForSymbolName(IDiaSymbol *pGlobalScope, const wchar_t *nameToFind);
