#pragma once
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include "Minidump.h"
#include "Symbols.h"

PBYTE PF_FindAddressInMemory(PPF_MAPFILE pMapFile, ULONG64 Source, ULONG64 Length);
ULONG64 PF_FindAddressInMemoryForSymbol(wchar_t *ModuleSymbol, PPF_MODULE_INFOS pModulesInfos);