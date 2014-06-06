#pragma once
#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <sddl.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <bcrypt.h>
#include <stdio.h>
#include <wchar.h>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dbghelp.h>
#include "Minidump.h"
#include "Memory.h"

#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef unsigned char BYTE;

/*
FROM
Benjamin DELPY `gentilkiwi`
http://blog.gentilkiwi.com
benjamin@gentilkiwi.com
*/

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[ANYSIZE_ARRAY]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;     // 'UUUR'                             55555552
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} KIWI_BCRYPT_GEN_KEY, *PKIWI_BCRYPT_GEN_KEY;

typedef struct _KIWI_GENERIC_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
} KIWI_GENERIC_PRIMARY_CREDENTIAL, *PKIWI_GENERIC_PRIMARY_CREDENTIAL;
/* END FROM */

typedef struct _PF_LIST_ENTRY
{
	ULONG64	FLink;
	ULONG64	BLink;
	ULONG	unk1;
	ULONG64	This;
	LUID	Luid;
	ULONG	unk3;
	ULONG	unk4;
	KIWI_GENERIC_PRIMARY_CREDENTIAL Credentials;
}PF_LIST_ENTRY, *PPF_LIST_ENTRY;


NTSTATUS PF_InitializeCrypto3DesProvider(PKIWI_BCRYPT_GEN_KEY pProvider);
NTSTATUS PF_InitializeCryptoAesProvider(PKIWI_BCRYPT_GEN_KEY pProvider);
bool PF_AcquireKeyFromSymbol(PPF_MAPFILE pMapFile, PBYTE pKey, PKIWI_BCRYPT_GEN_KEY pGenKey);