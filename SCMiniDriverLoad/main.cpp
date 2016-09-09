#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "Logger.h"
#include "inc_cpdk\cardmod.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#if 0
#define				APP_HOOKING_W	L"C:\\Yubico\\open_src_my\\SCMiniDriverTest\\x64\\Debug\\SCMiniDriverTest.exe"
#else
#define				APP_HOOKING_W	L"C:\\Windows\\system32\\LogonUI.exe"
#endif
#if 0
#define				DLL_HOOKED_W	L"ybmd.dll"
#define				DLL_HOOKED		"ybmd.dll"
#else
#define				DLL_HOOKED_W	L"msclmd.dll"
#define				DLL_HOOKED		"msclmd.dll"
#endif
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;
//PCARD_DATA			g_pCardData = 0;


//initialization of MS Class Mini-driver API function pointers
PFN_CARD_ACQUIRE_CONTEXT	pOrigCardAcquireContext = NULL;


//CardAcquireContext
DWORD WINAPI
CardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	PCARD_DATA	pOrigCardData;
	DWORD		dwRet;

	if (logger) {
		logger->TraceInfo("CardAcquireContext");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	pOrigCardData = (PCARD_DATA)calloc(1, sizeof(CARD_DATA));
	dwRet = pOrigCardAcquireContext(pOrigCardData, dwFlags);

	memcpy(pCardData, pOrigCardData, sizeof(CARD_DATA));
	pCardData->pbAtr = pOrigCardData->pbAtr;
	pCardData->cbAtr = pOrigCardData->cbAtr;
	pCardData->dwVersion = pOrigCardData->dwVersion;
	pCardData->hScard = pOrigCardData->hScard;
	pCardData->hSCardCtx = pOrigCardData->hSCardCtx;

	pCardData->pfnCardAuthenticateChallenge = pOrigCardData->pfnCardAuthenticateChallenge;
	pCardData->pfnCardAuthenticateEx = pOrigCardData->pfnCardAuthenticateEx;
	pCardData->pfnCardAuthenticatePin = pOrigCardData->pfnCardAuthenticatePin;
	pCardData->pfnCardChangeAuthenticator = pOrigCardData->pfnCardChangeAuthenticator;
	pCardData->pfnCardChangeAuthenticatorEx = pOrigCardData->pfnCardChangeAuthenticatorEx;
	pCardData->pfnCardConstructDHAgreement = pOrigCardData->pfnCardConstructDHAgreement;
	pCardData->pfnCardCreateContainer = pOrigCardData->pfnCardCreateContainer;
	pCardData->pfnCardCreateDirectory = pOrigCardData->pfnCardCreateDirectory;
	pCardData->pfnCardCreateFile = pOrigCardData->pfnCardCreateFile;
	pCardData->pfnCardDeauthenticate = pOrigCardData->pfnCardDeauthenticate;
	pCardData->pfnCardDeauthenticateEx = pOrigCardData->pfnCardDeauthenticateEx;
	pCardData->pfnCardDeleteContainer = pOrigCardData->pfnCardDeleteContainer;
	pCardData->pfnCardDeleteContext = pOrigCardData->pfnCardDeleteContext;
	pCardData->pfnCardDeleteDirectory = pOrigCardData->pfnCardDeleteDirectory;
	pCardData->pfnCardDeleteFile = pOrigCardData->pfnCardDeleteFile;
	pCardData->pfnCardDeriveKey = pOrigCardData->pfnCardDeriveKey;
	pCardData->pfnCardDestroyDHAgreement = pOrigCardData->pfnCardDestroyDHAgreement;
	pCardData->pfnCardEnumFiles = pOrigCardData->pfnCardEnumFiles;
	pCardData->pfnCardGetChallenge = pOrigCardData->pfnCardGetChallenge;
	pCardData->pfnCardGetChallengeEx = pOrigCardData->pfnCardGetChallengeEx;
	pCardData->pfnCardGetContainerInfo = pOrigCardData->pfnCardGetContainerInfo;
	pCardData->pfnCardGetContainerProperty = pOrigCardData->pfnCardGetContainerProperty;
	pCardData->pfnCardGetFileInfo = pOrigCardData ->pfnCardGetFileInfo;
	pCardData->pfnCardGetProperty = pOrigCardData->pfnCardGetProperty;
	pCardData->pfnCardQueryCapabilities = pOrigCardData->pfnCardQueryCapabilities;
	pCardData->pfnCardQueryFreeSpace = pOrigCardData->pfnCardQueryFreeSpace;
	pCardData->pfnCardQueryKeySizes = pOrigCardData->pfnCardQueryKeySizes;
	pCardData->pfnCardReadFile = pOrigCardData->pfnCardReadFile;
	pCardData->pfnCardRSADecrypt = pOrigCardData->pfnCardRSADecrypt;
	pCardData->pfnCardSetContainerProperty = pOrigCardData->pfnCardSetContainerProperty;
	pCardData->pfnCardSetProperty = pOrigCardData->pfnCardSetProperty;
	pCardData->pfnCardSignData = pOrigCardData->pfnCardSignData;
	pCardData->pfnCardUnblockPin = pOrigCardData->pfnCardUnblockPin;
	pCardData->pfnCardWriteFile = pOrigCardData->pfnCardWriteFile;

	return dwRet;
}


#if 0
//CardDeleteContext
DWORD WINAPI
CardDeleteContext(
	__inout		PCARD_DATA	pCardData
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteContext");
	}
	return g_pCardData->pfnCardDeleteContext(pCardData);
}
#endif


//////////////////////////////////////////////////////////////////////////////////////
//
//	Private Helper Functions
//
//////////////////////////////////////////////////////////////////////////////////////

//shouldHook
bool shouldHook() {
	wchar_t	wProcessName[MAX_PATH];
	GetModuleFileName(NULL, wProcessName, MAX_PATH);
	std::wstring wsPN(wProcessName);//convert wchar* to wstring
	std::string strProcessName(wsPN.begin(), wsPN.end());
	if (0 == wcscmp(APP_HOOKING_W, wProcessName)) {
		logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
		if (logger) { logger->TraceInfo("%s is calling %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	g_hDll = LoadLibrary(DLL_HOOKED_W);

	//GetProcAddress
	pOrigCardAcquireContext = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CardAcquireContext");
}


//hookFinalize
void hookFinalize() {
	//g_pCardData = NULL;
}


//DllMain
BOOL WINAPI DllMain(
	__in HINSTANCE  hInstance,
	__in DWORD      Reason,
	__in LPVOID     Reserved
)
{
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		if (shouldHook()) {
			hookInitialize();
		} else {
			return FALSE;
		}
		break;

	case DLL_PROCESS_DETACH:
		hookFinalize();
		break;
	}
	return TRUE;
}