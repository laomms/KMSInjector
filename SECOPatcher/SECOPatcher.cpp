
#if _MSC_VER >= 1200
#pragma warning(push)
#pragma warning(disable:4201) // C4201: nonstandard extension used : nameless struct/union
#endif

#define _WIN32_MAXVER           0x0601
#define _WIN32_WINDOWS_MAXVER   0x0601
#define NTDDI_MAXVER            0x06010000
#define _WIN32_IE_MAXVER        0x0800
#define _WIN32_WINNT_MAXVER     0x0601
#define WINVER_MAXVER           0x0601

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x05010300
#endif

struct IUnknown; // Workaround for "combaseapi.h(229): error C2760: syntax error: unexpected token 'identifier', expected 'type specifier'" when using /permissive-

#include <SDKDDKVer.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <imagehlp.h>
#include <Rpc.h>
#include <stdio.h>
#include <stdlib.h>

// Main dll filename
#define DLL_NAME L"SECOPatcher.dll"

// Fake KMS host IP address
#define LOCALHOST_IP L"127.0.0.1"
#define PROTO_SEQ_TCP L"ncacn_ip_tcp"

// Function typedef
typedef HMODULE(WINAPI *pfnLoadLibraryW)(LPCWSTR lpFileName);
typedef RPC_STATUS(RPC_ENTRY *pfnRpcStringBindingComposeW)(WCHAR *ObjUuid, WCHAR *ProtSeq, WCHAR *NetworkAddr, WCHAR *EndPoint, WCHAR *Options, WCHAR **StringBinding);

// Hook functions prototype
HMODULE WINAPI LoadLibraryW_Hook(LPCWSTR lpFileName);
RPC_STATUS RPC_ENTRY RpcStringBindingComposeW_Hook(WCHAR *ObjUuid, WCHAR *ProtSeq, WCHAR *NetworkAddr, WCHAR *EndPoint, WCHAR *Options, WCHAR **StringBinding);

typedef struct _APIHook {
	const char *module;
	const char *name;
	void* hook;
	void* original;
} APIHook;

#include <strsafe.h>

#ifdef _DEBUG
#   define OutputDebugStringEx( str, ... ) \
      { \
        WCHAR c[512]; \
        swprintf_s( c, _countof(c), str, __VA_ARGS__ ); \
        OutputDebugStringW( c ); \
      }
#else
#    define OutputDebugStringEx( str, ... )
#endif

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif

#pragma comment(linker, "/merge:.pdata=.rdata")

// Function prototype
BOOL WINAPI PatchIAT(HMODULE hModule);

// Original function pointers
#define DEFINE_HOOK(module, name) { module, #name, (void*)name##_Hook, NULL } 
#define GET_ORIGINAL_STORE(name) (&APIHooks[name##_Index].original)
#define CALL_ORIGINAL_FUNC(name, ...) (*(pfn##name)(APIHooks[name##_Index].original))(__VA_ARGS__)

typedef enum _APIIndex {
	LoadLibraryW_Index = 0,
	RpcStringBindingComposeW_Index,
} APIIndex;

APIHook APIHooks[] =
{
	DEFINE_HOOK("kernel32.dll", LoadLibraryW),
	DEFINE_HOOK("rpcrt4.dll", RpcStringBindingComposeW),
};

HMODULE WINAPI LoadLibraryW_Hook(LPCWSTR lpFileName)
{
	HMODULE hModule = CALL_ORIGINAL_FUNC(LoadLibraryW, lpFileName);

	if (hModule == NULL)
	{
		SetLastError(GetLastError());
		return NULL;
	}

	OutputDebugStringEx(L"[SppExtComObjHook] LoadLibraryW called. [lpFileName: %s, base: 0x%p]\n", lpFileName, hModule);

	if (!_wcsicmp(lpFileName, L"OSPPOBJS.DLL") && !_wcsicmp(lpFileName, L"SPPOBJS.DLL"))
	{
		OutputDebugStringEx(L"[SppExtComObjHook] Not a target module. Skipped patching...\n");
		return hModule;
	}

	PatchIAT(hModule);

	return hModule;
}

RPC_STATUS RPC_ENTRY RpcStringBindingComposeW_Hook(WCHAR *ObjUuid, WCHAR *ProtSeq, WCHAR *NetworkAddr, WCHAR *EndPoint, WCHAR *Options, WCHAR **StringBinding)
{
	OutputDebugStringEx(L"[SppExtComObjHook] RpcStringBindingComposeW called [ProtSeq: %s, NetWorkAddr: %s, EndPoint: %s].\n", ProtSeq, NetworkAddr, EndPoint);

	// Check destination address and hook
	if (ProtSeq != nullptr && _wcsicmp(ProtSeq, PROTO_SEQ_TCP) == 0)
	{
		// Redirect rpcrt4 call to localhost
		OutputDebugStringEx(L"[SppExtComObjHook] Replaced NetworkAddr from %s to %s\n", NetworkAddr, LOCALHOST_IP);

		NetworkAddr = (wchar_t*)(LOCALHOST_IP);
	}

	// Call original function
	return CALL_ORIGINAL_FUNC(RpcStringBindingComposeW, ObjUuid, ProtSeq, NetworkAddr, EndPoint, Options, StringBinding);
}

PIMAGE_IMPORT_DESCRIPTOR WINAPI GetImportDescriptor(HMODULE hModule)
{
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_DATA_DIRECTORY pDirectory;
	ULONG_PTR Address;
	LPBYTE pb = (LPBYTE)hModule;

	if (((WORD *)pb)[0] != IMAGE_DOS_SIGNATURE)
		return nullptr;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pNtHeaders = (PIMAGE_NT_HEADERS)(pb + pDosHeader->e_lfanew);

	if (((DWORD *)pNtHeaders)[0] != IMAGE_NT_SIGNATURE)
		return nullptr;

	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pDirectory = &pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	Address = pDirectory->VirtualAddress;

	if (Address == 0)
		return nullptr;

	return (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)hModule + Address);
}

// Create RpcStringBindingComposeW and GetProcAddressHook hooks
BOOL WINAPI PatchIATInternal(HMODULE hModule, APIHook* APIHookInfo)
{
	// Get original function addresses being hooked
	FARPROC Original = GetProcAddress(GetModuleHandleA(APIHookInfo->module), APIHookInfo->name);
	if (Original == nullptr)
		return FALSE;

	// Hold original address
	if (APIHookInfo->original == nullptr)
		APIHookInfo->original = (void*)Original;

	// Get base address of our process primary module
	ULONG_PTR BaseAddress = (ULONG_PTR)hModule;

	// Get import table
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = GetImportDescriptor(hModule);

	if (pImageImportDescriptor == nullptr)
		return FALSE;

	// Search through import table
	for (; pImageImportDescriptor->Name; pImageImportDescriptor++)
	{

		LPCSTR lpDllName = (LPCSTR)(BaseAddress + pImageImportDescriptor->Name);

		if (_stricmp(lpDllName, APIHookInfo->module))
			continue;

		PIMAGE_THUNK_DATA pImageThunkData = (PIMAGE_THUNK_DATA)(BaseAddress + pImageImportDescriptor->FirstThunk);
		PIMAGE_THUNK_DATA pOrgImageThunkData = (PIMAGE_THUNK_DATA)(BaseAddress + pImageImportDescriptor->OriginalFirstThunk);

		for (; pImageThunkData->u1.Function; pImageThunkData++, pOrgImageThunkData++)
		{
			FARPROC pfnImportedFunc = (FARPROC)(pImageThunkData->u1.Function);

			// Patch
			if (pfnImportedFunc == Original)
			{
				OutputDebugStringEx(L"[SppExtComObjHook] Replaced %S import 0x%p @ 0x%p with hook entry 0x%p in base 0x%p.\n",
					APIHookInfo->name, (void*)pImageThunkData->u1.Function, (void*)(&pImageThunkData->u1.Function), APIHookInfo->hook, hModule);
				DWORD flOldProtect;
				VirtualProtect(pImageThunkData, sizeof(ULONG_PTR), PAGE_READWRITE, &flOldProtect);
				WriteProcessMemory(GetCurrentProcess(), pImageThunkData, &APIHookInfo->hook, sizeof(ULONG_PTR), nullptr);
				VirtualProtect(pImageThunkData, sizeof(ULONG_PTR), flOldProtect, &flOldProtect);
			}
		}
	}

	return TRUE;
}

BOOL WINAPI PatchIAT(HMODULE hModule)
{
	BOOL bRet = TRUE;

	for (int i = 0; i < _countof(APIHooks); i++)
	{
		if (!PatchIATInternal(hModule, &APIHooks[i]))
		{
			bRet = FALSE;
			break;
		}
	}

	return bRet;
}


BOOL WINAPI PauseResumeThreadList(DWORD dwOwnerPID, BOOL bResumeThread)
{
	HANDLE hThreadSnap = nullptr;
	BOOL bRet = FALSE;
	THREADENTRY32 te32 = { 0 };

	// Take a snapshot of all threads currently in the system. 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Walk the thread snapshot to find all threads of the process. 
	// If the thread belongs to the process, add its information 
	// to the display list.
	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == dwOwnerPID)
			{
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);

				if (bResumeThread)
					ResumeThread(hThread);
				else
					SuspendThread(hThread);

				CloseHandle(hThread);
			}

		} while (Thread32Next(hThreadSnap, &te32));

		bRet = TRUE;
	}

	// Do not forget to clean up the snapshot object. 
	CloseHandle(hThreadSnap);

	return bRet;
}

BOOL WINAPI FindProcessIdByName(LPCWSTR lpPrimaryModuleName, DWORD *lpProcessId)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(pe32);

	BOOL bRet = FALSE;

	if (Process32FirstW(hProcessSnap, &pe32))
	{
		do
		{
			if (pe32.szExeFile != nullptr && !_wcsicmp(pe32.szExeFile, lpPrimaryModuleName))
			{
				bRet = TRUE;
				*lpProcessId = pe32.th32ProcessID;
			}

		} while (Process32NextW(hProcessSnap, &pe32));
	}

	CloseHandle(hProcessSnap);

	return bRet;
}

BOOL WINAPI InjectDll(LPCWSTR lpDllName, DWORD dwProcessId)
{
	BOOL bRet = FALSE;

	HANDLE hProcess = nullptr;
	LPVOID addrDllPath = nullptr;

	do
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (nullptr == hProcess)
			break;

		SIZE_T allocSize = (wcslen(lpDllName) + 1) * sizeof(WCHAR);
		addrDllPath = VirtualAllocEx(hProcess, nullptr, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (nullptr == addrDllPath)
			break;

		if (!WriteProcessMemory(hProcess, addrDllPath, lpDllName, allocSize, nullptr))
			break;

		pfnLoadLibraryW addrLoadLibraryW = (pfnLoadLibraryW)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
		if (addrLoadLibraryW == nullptr)
			break;

		HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)addrLoadLibraryW, addrDllPath, 0, nullptr);
		if (hThread == nullptr)
			break;

		WaitForSingleObject(hThread, INFINITE);

		// This may be wrong on x64 because LoadLibrary returns HMODULE -> 64-bit
		DWORD dwExitCode;
		GetExitCodeThread(hThread, &dwExitCode);
		CloseHandle(hThread);

		if (dwExitCode != 0)
			bRet = TRUE;

	} while (FALSE);

	if (addrDllPath != nullptr)
		VirtualFreeEx(hProcess, addrDllPath, 0, MEM_RELEASE);
	if (hProcess != nullptr)
		CloseHandle(hProcess);

	return bRet;
}

void InitHook(void)
{
	return;
}

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpvReserved);

	OutputDebugStringEx(L"[SppExtComObjHook] DllMain entry. [nReason: %u]\n", fdwReason);

	BOOL bRet = TRUE;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		wchar_t CurrentExePath[MAX_PATH];
		GetModuleFileNameW(NULL, CurrentExePath, MAX_PATH);
		wchar_t* CurrentExeName = wcsrchr(CurrentExePath, L'\\') + 1;
		if (0 == _wcsicmp(CurrentExeName, L"rundll32.exe"))
		{

		}
		else
		{
			bRet = DisableThreadLibraryCalls(hinstDLL) && PatchIAT(GetModuleHandleA(nullptr));
		}

		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return bRet;
}

void CALLBACK PatcherMain(HWND hWnd, HINSTANCE hInstance, LPWSTR lpCmdLine, int nShowCmd)
{
	UNREFERENCED_PARAMETER(hWnd);
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(nShowCmd);

	STARTUPINFO si;
	PROCESS_INFORMATION pi = { 0 };
	DWORD dwRet = ERROR_SUCCESS;
	BOOL bRet;

	DWORD SppSvcPid = 0;

	if (nullptr != wcsstr(lpCmdLine, L"SppExtComObj.exe") && FindProcessIdByName(L"sppsvc.exe", &SppSvcPid))
	{
		PauseResumeThreadList(SppSvcPid, FALSE);
		OutputDebugStringEx(L"[SppExtComObjPatcher] Process sppsvc.exe [pid: %u] suspended.\n", SppSvcPid);
	}

	GetStartupInfoW(&si);

	bRet = CreateProcessW(nullptr, lpCmdLine, nullptr, nullptr, FALSE, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | DETACHED_PROCESS, nullptr, nullptr, &si, &pi);
	if (!bRet)
	{
		dwRet = GetLastError();
		OutputDebugStringEx(L"[SppExtComObjPatcher] CreateProcess failed [cmdLine: %s, error: 0x%08u].\n", lpCmdLine, dwRet);
		goto fail;
	}

	bRet = DebugActiveProcessStop(pi.dwProcessId);
	if (!bRet)
	{
		dwRet = GetLastError();
		OutputDebugStringEx(L"[SppExtComObjPatcher] DebugActiveProcessStop failed [error: 0x%08u].\n", dwRet);
		goto fail;
	}

	OutputDebugStringEx(L"[SppExtComObjPatcher] CreateProcess succeeded [cmdLine: %s, pid: %u, tid: %u].\n", lpCmdLine, pi.dwProcessId, pi.dwThreadId);
	Sleep(100);
	// SuspendThread(pi.hThread);
	InjectDll(DLL_NAME, pi.dwProcessId);

fail:
	ResumeThread(pi.hThread);

	if (SppSvcPid != 0)
	{
		PauseResumeThreadList(SppSvcPid, TRUE);
		OutputDebugStringEx(L"[SppExtComObjPatcher] Process sppsvc.exe [pid: %u] resumed.\n", SppSvcPid);
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &dwRet);
	OutputDebugStringEx(L"[SppExtComObjPatcher] Process %s [pid: %u] exited with code %u.\n", lpCmdLine, pi.dwProcessId, dwRet);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	ExitProcess(dwRet);
}
