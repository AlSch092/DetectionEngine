//By Alsch092 @ Github
#pragma once
#include "HandleGuard.hpp"
#include "EncryptedStr.hpp"
#include "Definitions.hpp"
#include "WMI.hpp"
#include <stdint.h>
#include <sstream>
#include <vector>

#ifdef _LOGGING_ENABLED
#include <stdio.h>
#include <iostream>
#endif

#include <TlHelp32.h>
#include <Psapi.h>

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif


struct ModuleInfoMini
{
    uintptr_t baseAddress;
    uintptr_t size;
};

struct MODULE_DATA
{
    std::wstring baseName;
    std::wstring name; //full path
    MODULEINFO dllInfo;
    HMODULE hModule = 0;
    size_t size = 0;

    bool operator ==(const MODULE_DATA& other) const noexcept
    {
        return (baseName == other.baseName && hModule == other.hModule);
    }
};

class ProcessHelper final
{
public:

    static bool IsProcessWoW64(HANDLE hProcess)
    {
        using IsWow64Process2_t = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

        static auto pIsWow64Process2 = reinterpret_cast<IsWow64Process2_t>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));

        if (pIsWow64Process2)
        {
            USHORT p, m;
            if (pIsWow64Process2(hProcess, &p, &m))
                return m != IMAGE_FILE_MACHINE_UNKNOWN && m != IMAGE_FILE_MACHINE_AMD64 && m != IMAGE_FILE_MACHINE_ARM64;
        }

        BOOL wow64 = FALSE;

        if (IsWow64Process(hProcess, &wow64))
            return wow64 != FALSE;

        return false;
    }

    static std::wstring GetProcessImagePath(HANDLE hProcess)
    {
        wchar_t buf[1024]{ 0 };
        DWORD size = sizeof(buf) / sizeof(wchar_t);
        if (QueryFullProcessImageNameW(hProcess, 0, buf, &size))
        {       
            return std::wstring(buf);
        }
        return L"";
    }

    static uint8_t* ReadRemoteSection(__in const DWORD pid, __in const char* section, __out int& bytesRead)
    {
        bytesRead = 0;

        if (pid <= 4) //system processes
        {        
            return nullptr;
        }

        HandleGuard hProcess = HandleGuard(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));

        if (!hProcess)
        {
#ifdef _LOGGING_ENABLED
            printf("Failed to open process. Error: %d\n", GetLastError());
#endif
            bytesRead = 0;
            return nullptr;
        }

        SIZE_T sectionSize = 0;
        uintptr_t baseAddress = 0;

        if (!GetRemoteSectionAddress(hProcess, section, baseAddress, sectionSize))
        {
#ifdef _LOGGING_ENABLED
            printf("Failed to find the .text section.");
#endif
            bytesRead = 0;
            return nullptr;
        }

        if (sectionSize == 0)
            return nullptr;

        uint8_t* buffer = new uint8_t[sectionSize];

        SIZE_T RPMBytesRead = 0;

        if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress), buffer, sectionSize, (SIZE_T*)&RPMBytesRead))
        {
#ifdef _LOGGING_ENABLED
            //printf("Failed to read memory. Error: %d\n", GetLastError());
#endif
            bytesRead = 0;
            return nullptr;
        }

        bytesRead = RPMBytesRead;
        return buffer;
    }


    static uint8_t* ReadRemoteSectionWoW64(__in const DWORD pid, __in const char* section, __out int& readSize)
    {
        if (pid <= 4) //system processes
        {
            readSize = 0;
            return nullptr;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        if (!hProcess)
        {
#ifdef _LOGGING_ENABLED
            printf("Failed to open process. Error: %d", GetLastError());
#endif
            readSize = 0;
            return nullptr;
        }

        SIZE_T sectionSize = 0;

        uint8_t* buffer = new uint8_t[sectionSize];

        ULONGLONG baseAddress = 0;

        ULONGLONG textAddr = 0;
        SIZE_T textSize = 0;

        if (!GetRemoteSectionAddressWoW64(hProcess, section, textAddr, textSize))
        {
            printf("Failed to fetch remote text sction addr!\n");
            readSize = 0;
            return nullptr;
        }

        int bytesRead = 0;
        buffer = WoW64Readx64Memory(hProcess, baseAddress, sectionSize, bytesRead);

        readSize = bytesRead;
        CloseHandle(hProcess);
        return buffer;
    }

    static bool GetRemoteSectionAddress(__in const HANDLE hProcess, __in const char* sectionName, __out uintptr_t& baseAddress, __out SIZE_T& sectionSize)
    {
        HMODULE hModule = nullptr;
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess)); //fetch base address of hProcess
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return false;

        if (Module32First(hSnapshot, &me32)) //fetch base address of image in target process
            hModule = me32.hModule;

        if (hSnapshot)
            CloseHandle(hSnapshot);

        if (!hModule)
            return false;

        IMAGE_DOS_HEADER dosHeader;
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(dosHeader), &bytesRead) || bytesRead != sizeof(dosHeader))
            return false;

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hModule + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), &bytesRead) || bytesRead != sizeof(ntHeaders))
            return false;

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
            return false;

        IMAGE_SECTION_HEADER sectionHeader;
        uintptr_t sectionOffset = (uintptr_t)hModule + dosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

        for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
        {
            if (!ReadProcessMemory(hProcess, (LPCVOID)sectionOffset, &sectionHeader, sizeof(sectionHeader), &bytesRead) || bytesRead != sizeof(sectionHeader))
                return false;

            if (strcmp((const char*)sectionHeader.Name, sectionName) == 0)
            {
                baseAddress = (uintptr_t)hModule + sectionHeader.VirtualAddress;
                sectionSize = sectionHeader.Misc.VirtualSize;
                return true;
            }

            sectionOffset += sizeof(IMAGE_SECTION_HEADER);
        }

        return false;
    }

    /*
        GetRemoteSectionAddressWow64 - grab remote .text address of x64 process (from WoW64 process)
        "Get remote section address of a 64‑bit process, while my current process is a 32‑bit WoW64 process.
    */
    static bool GetRemoteSectionAddressWoW64(__in const HANDLE hProcess, __in const char* sectionName, __out ULONGLONG& baseAddress, __out SIZE_T& sectionSize)
    {
       
        // Load function pointers
        HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
        if (!hNtDll)
        {
            //std::cerr << "Failed to load ntdll.dll." << std::endl;
            return false;
        }

        auto NtWow64QueryInformationProcess64 = (pNtWow64QueryInformationProcess64)
            GetProcAddress(hNtDll, "NtWow64QueryInformationProcess64");

        auto NtWow64ReadVirtualMemory64 = (pNtWow64ReadVirtualMemory64)
            GetProcAddress(hNtDll, "NtWow64ReadVirtualMemory64");

        if (!NtWow64QueryInformationProcess64 || !NtWow64ReadVirtualMemory64)
        {
            return false;
        }

        // Get 64-bit PEB address
        PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
        ULONG returnLength;
        NTSTATUS status = NtWow64QueryInformationProcess64(hProcess, 0, &pbi64, sizeof(pbi64), &returnLength);

        if (status != 0)
        {
            return false;
        }

        if (!pbi64.PebBaseAddress)
        {
            return false;
        }

        // Read 64-bit PEB structure
        PEB64 peb64 = { 0 };
        ULONG64 bytesRead = 0;
        status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)pbi64.PebBaseAddress, &peb64, sizeof(peb64), &bytesRead);

        if (status != 0 || bytesRead != sizeof(peb64))
        {
            //std::cerr << "Failed to read 64-bit PEB. NTSTATUS: " << std::hex << status << std::endl;
            return false;
        }

        ULONGLONG imageBase = (ULONGLONG)peb64.ImageBaseAddress;
        //std::cout << "64-bit Image Base Address: " << std::hex << imageBase << std::endl;

        // Read DOS Header
        IMAGE_DOS_HEADER dosHeader;
        status = NtWow64ReadVirtualMemory64(hProcess, (PVOID64)imageBase, &dosHeader, sizeof(dosHeader), &bytesRead);

        if (status != 0 || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            //std::cerr << "Failed to read DOS header." << std::endl;
            return false;
        }

        // Read NT Headers
        IMAGE_NT_HEADERS64 ntHeaders;
        status = NtWow64ReadVirtualMemory64(
            hProcess,
            (PVOID64)(imageBase + dosHeader.e_lfanew),
            &ntHeaders,
            sizeof(ntHeaders),
            &bytesRead
        );

        if (status != 0 || ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        {
            printf("Failed to read NT headers.\n");
            return false;
        }

        // Read Section Headers
        int numSections = ntHeaders.FileHeader.NumberOfSections;
        ULONGLONG sectionHeaderAddr = imageBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
        IMAGE_SECTION_HEADER sectionHeader;

        for (int i = 0; i < numSections; i++)
        {
            status = NtWow64ReadVirtualMemory64(
                hProcess,
                (PVOID64)(sectionHeaderAddr + (i * sizeof(IMAGE_SECTION_HEADER))),
                &sectionHeader,
                sizeof(sectionHeader),
                &bytesRead
            );

            if (status != 0)
            {
                continue;
            }

            if (strcmp((char*)sectionHeader.Name, sectionName) == 0)
            {
                baseAddress = imageBase + sectionHeader.VirtualAddress;
                sectionSize = sectionHeader.Misc.VirtualSize;
                return true;
            }
        }

        return false;
    }

    //read x64 memory from WoW64 (32-bit) process
    static uint8_t* WoW64Readx64Memory(__in HANDLE hProc, __in const ULONGLONG BaseAddress, __in const int numBytes, __out int& numBytesRead)
    {
        numBytesRead = 0;

        typedef NTSTATUS(NTAPI* pNtWow64ReadVirtualMemory64)(
            HANDLE ProcessHandle,
            PVOID64 BaseAddress,
            PVOID Buffer,
            ULONG64 Size,
            PULONG64 NumberOfBytesRead
            );

        auto NtWow64ReadVirtualMemory64 = (pNtWow64ReadVirtualMemory64)
            GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtWow64ReadVirtualMemory64");

        if (!NtWow64ReadVirtualMemory64)
        {
            CloseHandle(hProc);
            return nullptr;
        }

        uint8_t* buffer = new uint8_t[numBytes];
        ULONG64 bytesRead = 0;

        NTSTATUS status = NtWow64ReadVirtualMemory64(hProc, (PVOID64)BaseAddress, buffer, numBytes, &bytesRead);

        if (status != 0)
        {
#ifdef _LOGGING_ENABLED
            printf("Failed to call NtWow64ReadVirtualMemory64. Error: %x\n", GetLastError());
#endif
            CloseHandle(hProc);
            return nullptr;
        }

        numBytesRead = bytesRead;
        return buffer;
    }

    static std::wstring GetProcessPathByPID(__in const DWORD pid)
    {
        //IWbemServices* pServices = WMI::ConnectToWMI();

//        IEnumWbemClassObject* pEnumerator = NULL;
//        HRESULT hres;
//
//        if (!wmi)
//        {
//#ifdef _LOGGING_ENABLED
//            std::wcerr << L"wmi was null @ GetProcessPathByPID" << std::endl;
//#endif
//            return {};
//        }
//
//        const std::wstring queryText = L"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = ";
//
//        std::wstring query = std::wstring(queryText.c_str()) + std::to_wstring(pid);
//
//        BSTR queryLanguage = SysAllocString(L"WQL");
//
//        hres = wmi->ExecQuery(queryLanguage,_bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
//        SysFreeString(queryLanguage);
//
//        if (FAILED(hres))
//        {
//#ifdef _LOGGING_ENABLED
//            std::wcerr << L"Query for process path failed" << std::endl;
//#endif
//            return L"Error: Process path not found";
//        }
//
//        IWbemClassObject* pClassObject;
//        ULONG uReturn = 0;
//        std::wstring processPath = L"Not Available";
//
//        hres = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
//        if (uReturn == 0)
//        {
//#ifdef _LOGGING_ENABLED
//            std::wcerr << L"Process not found" << std::endl;
//#endif
//            return {};
//        }
//
//        VARIANT vtProp;
//        hres = pClassObject->Get(L"ExecutablePath", 0, &vtProp, 0, 0);
//
//        if (FAILED(hres) || vtProp.vt != VT_BSTR)
//        {
//#ifdef _LOGGING_ENABLED
//            std::wcerr << L"Could not retrieve executable path" << std::endl;
//#endif
//            return {};
//        }
//
//        processPath = vtProp.bstrVal;
//
//        // Clean up
//        pClassObject->Release();
//        pEnumerator->Release();
//        //pServices->Release();
//
//        return processPath;
        std::wstring result;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess)
        {
            wchar_t buffer[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, buffer, &size))
            {
                result.assign(buffer, size);
            }
            CloseHandle(hProcess);
        }
        return result;
    }

    static std::wstring GetProcessName(__in const DWORD pid)
    {
        typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

        std::wstring result;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) return L"";

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        auto NtQueryInformationProcess =
            (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        ULONG size = 0;
        NtQueryInformationProcess(hProc, ProcessImageFileName, NULL, 0, &size);
        if (size)
        {
            std::vector<BYTE> buffer(size);
            if (NT_SUCCESS(NtQueryInformationProcess(hProc, ProcessImageFileName, buffer.data(), size, &size)))
            {
                UNICODE_STRING* us = (UNICODE_STRING*)buffer.data();
                result.assign(us->Buffer, us->Length / sizeof(WCHAR));
            }
        }

        std::wstring exeName = result.substr(result.find_last_of(L"\\") + 1);

        CloseHandle(hProc);
        return exeName;
    }

    static bool IsPEHeader(__in unsigned char* pMemory)
    {
        __try
        {
            if (*((uint16_t*)pMemory) != IMAGE_DOS_SIGNATURE)
                return false;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pMemory;
        IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pMemory + pDosHeader->e_lfanew);

        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            return false;

        return true;
    }

    typedef struct _SYSTEM_HANDLE
    {
        ULONG ProcessId;
        BYTE ObjectTypeNumber;
        BYTE Flags;
        USHORT Handle;
        PVOID Object;
        ACCESS_MASK GrantedAccess;
        BOOL ReferencingOurProcess; //my own addition to the structure, we fill this member in ::DetectOpenHandlesToProcess
    } SYSTEM_HANDLE, * PSYSTEM_HANDLE;

    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG HandleCount;
        SYSTEM_HANDLE Handles[1];
    } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    typedef struct _PEB64
    {
        UCHAR InheritedAddressSpace;
        UCHAR ReadImageFileExecOptions;
        UCHAR BeingDebugged;
        UCHAR Spare;
        PVOID64 Mutant;
        PVOID64 ImageBaseAddress;  // Base address of main module
    } PEB64;

    typedef struct _PEB_LDR_DATA {
        BYTE Reserved1[8];
        PVOID Reserved2[3];
        LIST_ENTRY InMemoryOrderModuleList;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

    typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

    typedef struct _UNICODE_STRING
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;

    typedef struct _RTL_USER_PROCESS_PARAMETERS
    {
        BYTE           Reserved1[16];
        PVOID          Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID Reserved4[3];
        PVOID AtlThunkSListPtr;
        PVOID Reserved5;
        ULONG Reserved6;
        PVOID Reserved7;
        ULONG Reserved8;
        ULONG AtlThunkSListPtr32;
        PVOID Reserved9[45];
        BYTE Reserved10[96];
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
        BYTE Reserved11[128];
        PVOID Reserved12[1];
        ULONG SessionId;
    } PEB, * PPEB;

    typedef struct _PROCESS_BASIC_INFORMATION {
        PVOID Reserved1;
        PPEB PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;
    typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

    typedef NTSTATUS(NTAPI* PNT_QUERY_INFORMATION_PROCESS)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    typedef struct _PROCESS_BASIC_INFORMATION64 {
        ULONGLONG Reserved1;
        ULONGLONG PebBaseAddress; // 64-bit PEB Address
        ULONGLONG Reserved2[4];
    } PROCESS_BASIC_INFORMATION64;

    typedef NTSTATUS(NTAPI* pNtWow64QueryInformationProcess64)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );

    typedef NTSTATUS(NTAPI* pNtWow64ReadVirtualMemory64)(
        HANDLE ProcessHandle,
        PVOID64 BaseAddress,
        PVOID Buffer,
        ULONG64 Size,
        PULONG64 NumberOfBytesRead
        );

    typedef struct MY_PEB_LDR_DATA
    {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
        BOOLEAN ShutdownInProgress;
        PVOID ShutdownThreadId;
    } MY_PEB_LDR_DATA, * MY_PPEB_LDR_DATA;

    struct _MYPEB
    {
        UCHAR InheritedAddressSpace;
        UCHAR ReadImageFileExecOptions;
        UCHAR BeingDebugged;
        UCHAR Spare;
        PVOID Mutant;
        PVOID ImageBaseAddress;
        MY_PEB_LDR_DATA* Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    };


    typedef NTSTATUS(NTAPI* PNT_READ_VIRTUAL_MEMORY)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG NumberOfBytesToRead,
        PULONG NumberOfBytesRead
        );

    typedef enum _LDR_DLL_LOAD_REASON
    {
        LoadReasonStaticDependency,
        LoadReasonStaticLoad,
        LoadReasonDynamicLoad,
        LoadReasonAsImageLoad,
        LoadReasonAsDataLoad,
        LoadReasonEnclavePrimary,
        LoadReasonEnclaveDependency,
        LoadReasonPatchImage,
        LoadReasonUnknownReason = -1
    } LDR_DLL_LOAD_REASON;

    typedef struct _LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        USHORT LoadCount;
        USHORT TlsIndex;
        LIST_ENTRY HashLinks;
        PVOID SectionPointer;
        ULONG CheckSum;
        ULONG TimeDateStamp;
        // Windows 10 specific fields
        PVOID LoadedImports;
        PVOID EntryPointActivationContext; // Since Windows 10 1607 (Anniversary Update)
        PVOID PatchInformation;
        LDR_DLL_LOAD_REASON LoadReason;
    } MY_LDR_DATA_TABLE_ENTRY, * MY_PLDR_DATA_TABLE_ENTRY;

    /*
        GetModuleHandle_Ldr - returns base address of a module as HMODULE type
        returns NULL on failure
    */
    static HMODULE GetModuleHandle_Ldr(__in const  wchar_t* moduleName)
    {
#ifdef _M_IX86
        MYPEB* peb = (MYPEB*)__readfsdword(0x30);
#else
        _MYPEB* peb = (_MYPEB*)__readgsqword(0x60);
#endif

        uintptr_t kernel32Base = 0;

        LIST_ENTRY* current_record = NULL;
        LIST_ENTRY* start = &(peb->Ldr->InLoadOrderModuleList);

        current_record = start->Flink;

        while (true)
        {
            MY_LDR_DATA_TABLE_ENTRY* module_entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current_record, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            current_record = current_record->Flink;

            if (wcsstr(module_entry->FullDllName.Buffer, moduleName) != NULL)
            {
                return (HMODULE)module_entry->DllBase;
            }

            if (current_record == start)
            {
                return (HMODULE)NULL;
            }
        }

        return (HMODULE)NULL;
    }


    /*
        GetProcessCommandLine - fetches the command line of a process given its `processID`
        returns true on success, and fills `commandLine` with the command line of the process
    */
    static bool GetProcessCommandLine(__in const DWORD processID, __out std::wstring& commandLine)
    {
        commandLine = L"";

        if (processID <= 4)
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`processID` was system proc or NULL @ `GetProcessCommandLine`: " << std::endl;
#endif
            return false;
        }

        HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

        if (hNtDll == NULL)
        {
            hNtDll = LoadLibrary(TEXT("ntdll.dll"));

            if (hNtDll == NULL)
            {
#ifdef _LOGGING_ENABLED
                std::wcerr << L"`LoadLibrary` failed @ `GetProcessCommandLine`: " << GetLastError() << std::endl;
#endif
                return false;
            }

#ifdef _LOGGING_ENABLED
            std::wcerr << L"`ntdll.dll` hmodule was NULL @ `GetProcessCommandLine`" << std::endl;
#endif
            return false;
        }

        PNT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess = (PNT_QUERY_INFORMATION_PROCESS)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        PNT_READ_VIRTUAL_MEMORY NtReadVirtualMemory = (PNT_READ_VIRTUAL_MEMORY)GetProcAddress(hNtDll, "NtReadVirtualMemory");

        if (!NtQueryInformationProcess || !NtReadVirtualMemory)
        {
            return false;
        }

        HandleGuard hProcess = HandleGuard(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID));

        if (hProcess == NULL)
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`OpenProcess` failed @ `GetProcessCommandLine`: " << GetLastError() << std::endl;
#endif
            return false;
        }

        PROCESS_BASIC_INFORMATION pbi;
        ULONG len;

        NTSTATUS status = NtQueryInformationProcess(hProcess.get(), 0, &pbi, sizeof(pbi), &len);
        if (status != 0)
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`NtQueryInformationProcess` failed @ `GetProcessCommandLine`: " << GetLastError() << std::endl;
#endif
            return false;
        }

        _MYPEB peb;

        if (!ReadProcessMemory(hProcess.get(), pbi.PebBaseAddress, &peb, sizeof(_MYPEB), NULL))
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`ReadProcessMemory` (PEB) failed @ `GetProcessCommandLine`: " << GetLastError() << std::endl;
#endif
            return false;
        }

        RTL_USER_PROCESS_PARAMETERS procParams;

        if (!ReadProcessMemory(hProcess.get(), peb.ProcessParameters, &procParams, sizeof(_RTL_USER_PROCESS_PARAMETERS), NULL))
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`ReadProcessMemory` (peb.ProcesParameters) failed @ `GetProcessCommandLine`: " << GetLastError() << std::endl;
#endif
            return false;
        }

        wchar_t* cmdLine = new wchar_t[procParams.CommandLine.Length + 1] {0};

        if (!ReadProcessMemory(hProcess.get(), procParams.CommandLine.Buffer, (LPVOID)cmdLine, procParams.CommandLine.Length, NULL))
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`ReadProcessMemory` failed (procParams.CommandLine.Buffer) @ `GetProcessCommandLine`: " << GetLastError() << std::endl;
#endif
            return false;
        }

        commandLine = std::wstring(cmdLine);
        return true;
    }

    static std::vector<MODULE_DATA> GetLoadedModules()
    {

#ifdef _M_IX86
        MYPEB* peb = (MYPEB*)__readfsdword(0x30);
#else
        _MYPEB* peb = (_MYPEB*)__readgsqword(0x60);
#endif

        uintptr_t kernel32Base = 0;

        LIST_ENTRY* current_record = NULL;
        LIST_ENTRY* start = &(peb->Ldr->InLoadOrderModuleList);

        current_record = start->Flink;

        std::vector<MODULE_DATA> moduleList;

        while (true)
        {
            MY_LDR_DATA_TABLE_ENTRY* module_entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current_record, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            MODULE_DATA module;

            module.name = std::wstring(module_entry->FullDllName.Buffer);
            module.baseName = std::wstring(module_entry->BaseDllName.Buffer);

            module.hModule = (HMODULE)module_entry->DllBase;
            module.dllInfo.lpBaseOfDll = module_entry->DllBase;
            module.dllInfo.SizeOfImage = module_entry->SizeOfImage;
            moduleList.push_back(module);

            current_record = current_record->Flink;

            if (current_record == start)
            {
                break;
            }
        }

        return moduleList;
    }

    /*
        GetModuleSize - get size of a module at address `hModule` in current process
        returns the size of hModule, and 0 if hModule is invalid or error occurs
    */
    static DWORD GetModuleSize(__in const HMODULE hModule)
    {
        if (hModule == NULL)
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`hModule` was NULL @ `GetModuleSize`"  << std::endl;
#endif
            return 0;
        }

        MODULEINFO moduleInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo)))
        {
#ifdef _LOGGING_ENABLED
            std::wcerr << L"`GetModuleInformation` failed @ `GetModuleSize`: " << GetLastError() << std::endl;
#endif
            return 0;
        }

        return moduleInfo.SizeOfImage;
    }

    static HMODULE GetCurrentDllModule()
    {
        HMODULE hModule = NULL;
        // Pass the address of a symbol from this DLL
        if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&GetCurrentDllModule),
            &hModule))
        {
            return hModule;
        }
        return NULL;
    }

    static std::string GetCurrentDllPath()
    {
        char path[MAX_PATH] = { 0 };
        HMODULE hModule = GetCurrentDllModule();
        if (hModule && GetModuleFileNameA(hModule, path, MAX_PATH))
        {
            return std::string(path);
        }
        return {};
    }

    static bool IsAddressInModule(__in const std::vector<ModuleInfoMini>& modules, __in const uintptr_t address)
    {
        for (const auto& module : modules)
        {
            if (address >= module.baseAddress && address < (module.baseAddress + module.size))
            {
                return true; // Address is within a known module
            }
        }
        return false;
    }

};

