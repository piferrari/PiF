#include "stdafx.h"
#include "Symbols.h"

IDiaSymbol* PF_OpenAndFindGlobalScopeFromPdbFile(const wchar_t *szFilename)
{
	IDiaSession *pSession = NULL;
	IDiaSymbol *pGlobalScope = NULL;
	IDiaDataSource *pSource;

	HRESULT hr = CoCreateInstance(CLSID_DiaSource,
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(IDiaDataSource),
		(void **)&pSource);
	if (FAILED(hr))
	{
		fwprintf_s(stdout, L"Could not CoCreate CLSID_DiaSource.\n");
		return NULL;
	}

	if (FAILED(pSource->loadDataFromPdb(szFilename)))
	{
		fwprintf_s(stdout, L"loadDataFromPdb.\n");
		return NULL;
	}
	if (FAILED(pSource->openSession(&pSession)))
	{
		fwprintf_s(stdout, L"openSession.\n");
		pSession = 0;
		return NULL;
	}

	if (FAILED(pSession->get_globalScope(&pGlobalScope)))
	{
		fwprintf_s(stdout, L"globalscope.\n");
		pSession = 0;
		pGlobalScope = 0;
		return NULL;
	}
	pSession = 0;
	return pGlobalScope;
}

ULONG64 PF_GetVirtualAddressOffsetForSymbolName(IDiaSymbol *pGlobalScope, const wchar_t *nameToFind)
{
	ULONG length = wcslen(nameToFind);
	CComPtr<IDiaEnumSymbols> pEnum;
	pGlobalScope->findChildren(SymTagEnum::SymTagPublicSymbol, NULL, 0, &pEnum);

	CComPtr< IDiaSymbol > pSymbol;
	DWORD tag;
	DWORD celt;
	while (pEnum != NULL && SUCCEEDED(pEnum->Next(1, &pSymbol, &celt)) && celt == 1)
	{
		pSymbol->get_symTag(&tag);
		if (tag == SymTagPublicSymbol)
		{
			BSTR name;
			ULONG64 va;
			pSymbol->get_undecoratedNameEx(0x1000, &name);
			if (name != NULL)
			{
				if (wcscmp(name, nameToFind) == 0)
				{
					if (pSymbol->get_virtualAddress(&va) == S_OK)
						return va;
					else
						return 0;
				}
			}
		}
		pSymbol = NULL;
	}
	return 0;
}
