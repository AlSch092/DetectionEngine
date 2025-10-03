// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../ProcessHelper.hpp"
#include "../StrHelper.hpp"
#include <list>
#include <string>
#include <mutex>

class ProcessStringScanner : public IDetector
{
private:
    std::list<std::string> StringsToFind;
    bool bIsFixedTargetProcessId = false;
    std::mutex ListMutex;

public:
    ProcessStringScanner() = default;
    ~ProcessStringScanner() = default;

    ProcessStringScanner(__in const DetectionRule& rule)
    {
        this->Deserialize(rule);

        for (const auto& str : rule.Artifacts) //add blacklisted strings
        {
            this->AddString(str);
        }
    }

    void AddString(const std::string& str)
    {
        if (str.empty())
            return;

        std::lock_guard<std::mutex> lock(ListMutex);

        if (std::find(StringsToFind.begin(), StringsToFind.end(), str) == StringsToFind.end())
            StringsToFind.push_back(str);
    }
    
    void SetFixedProcessId(const bool bFixProcessId) noexcept { this->bIsFixedTargetProcessId = bFixProcessId; }
    void SetFixedProcessId(const uint32_t pid) noexcept { this->bIsFixedTargetProcessId = true; this->ProcessId = pid; }

    void SetTargetProcess(const uint32_t pid)
    {
        if (this->bIsFixedTargetProcessId)
            return;

        this->ProcessId = pid;
    }

    /*
    
    */
    DetectionResult Run() override
    {
        if (!this->Enabled())
            return {};

        DetectionResult result;
        result.Flag = DetectionFlags::NONE;
        this->RunCount++;

        bool bFoundFlaggedString = false;

        uintptr_t FoundFlaggedAtAddress = 0;

        HandleGuard hProc = HandleGuard(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, this->ProcessId));

        if (hProc.get() == INVALID_HANDLE_VALUE || hProc.get() == 0)
        {
#if _LOGGING_ENABLED
            std::cerr << "Failed to fetch processes handle @ ::Run: " << GetLastError() << std::endl;
#endif
            result.Flag = DetectionFlags::EXECUTION_ERROR;
            return result;
        }

        bool bIsCurrentProcessWoW64 = ProcessHelper::IsProcessWoW64(GetCurrentProcess());

        bool bTargetProcessWoW64 = ProcessHelper::IsProcessWoW64(hProc.get());

        uint8_t* buffer = nullptr;
        SIZE_T numBytesRead = 0;

        uintptr_t sectionAddress = 0; //needs to be 64-bit if target is x64, 32-bit if target is WoW64 ***
        SIZE_T sectionSize = 0;

        if (bIsCurrentProcessWoW64)  //we are WoW64
        {
            if (bTargetProcessWoW64) //is target process 32-bit (wow64)?
            {
                printf("Target process is WoW64\n");

                if (ProcessHelper::GetRemoteSectionAddress(hProc.get(), ".rdata", sectionAddress, sectionSize))  //todo: encrypt string
                {
                    if (sectionAddress == 0 || sectionSize == 0)
                    {
#ifdef _LOGGING_ENABLED
                        std::cerr << ".rdata sectionAddress or size was 0 @ ProcessStringScanner" << std::endl;
#endif
                        result.Flag = DetectionFlags::EXECUTION_ERROR;
                        return result;
                    }

                    buffer = new uint8_t[sectionSize];

                    if (!ReadProcessMemory(hProc.get(), (LPCVOID)sectionAddress, buffer, sectionSize, &numBytesRead)) //get .rdata section
                    {
#ifdef _LOGGING_ENABLED
                        std::cerr << "Failed to call RPM on .rdata" << std::endl;
#endif
                        if (buffer != nullptr)
                            delete[] buffer;

                        result.Flag = DetectionFlags::EXECUTION_ERROR;
                        return result;
                    }
                }
            }
            else //we are WoW64 and target is x64
            {
                printf("We are WoW64, target is x64\n");

                if (ProcessHelper::GetRemoteSectionAddressWoW64(hProc.get(), ".rdata", sectionAddress, sectionSize)) //WoW64 .dlls may not have a .rdata section!
                {
                    if (sectionAddress == 0 || sectionSize == 0)
                    {
#ifdef _LOGGING_ENABLED
                        std::cerr << ".rdata sectionAddress or size was 0 @ ProcessStringScanner" << std::endl;
#endif
                        result.Flag = DetectionFlags::EXECUTION_ERROR;
                        return result;
                    }
             
                    int numBytesRead = 0;

                    buffer = ProcessHelper::WoW64Readx64Memory(hProc.get(), sectionAddress, sectionSize, numBytesRead);

                    if (buffer == nullptr)
                    {
#ifdef _LOGGING_ENABLED
                        std::cerr << "Failed to read x64 memory from WoW64 @ ProcessStringScanner" << std::endl;
#endif
                        result.Flag = DetectionFlags::EXECUTION_ERROR;
                        return result;
                    }
                }
            }
        }
        else //we are 64 bit
        {
            printf("We are x64, target is x64\n");

            if (ProcessHelper::GetRemoteSectionAddress(hProc.get(), ".rdata", sectionAddress, sectionSize))  //todo: encrypt string
            {
                if (sectionAddress == 0 || sectionSize == 0)
                {
#ifdef _LOGGING_ENABLED
                    std::cerr << "sectionAddres or size was 0 at section: .rdata" << std::endl;
#endif
                    result.Flag = DetectionFlags::EXECUTION_ERROR;
                    return result;
                }

                buffer = new byte[sectionSize];
                
                bool rpmSuccess = ReadProcessMemory(hProc.get(), (LPCVOID)sectionAddress, buffer, sectionSize, &numBytesRead);

                if (!rpmSuccess)
                {
#ifdef _LOGGING_ENABLED
                    std::cerr << "Failed to call RPM on .rdata" << std::endl;
#endif
                    if (buffer != nullptr)
                        delete[] buffer;

                    result.Flag = DetectionFlags::EXECUTION_ERROR;
                    return result;
                }       
            }
        }
        
        for (const auto& str : StringsToFind)
        {
            std::wstring str_w = StrHelper::StringToWString(str);

            int size = str.length();
            int wstr_length = str_w.length();

            if (buffer != nullptr && numBytesRead > size) //get .rdata section
            {
                for (int i = 0; i < numBytesRead - size; i++)
                {
                    if (strncmp((const char*)&buffer[i], str.c_str(), size) == 0 || wcsncmp((const wchar_t*)&buffer[i], str_w.c_str(), wstr_length) == 0)
                    {
                        bFoundFlaggedString = true;
                        FoundFlaggedAtAddress = (uintptr_t)(sectionAddress + i);
                        break;
                    }
                }
            }
        }

        if (buffer != nullptr)
            delete[] buffer;

        if (bFoundFlaggedString)
        {
            result.Flag = DetectionFlags::BLACKLISTED_DATA_STRING;
            result.ProcessId = this->ProcessId;
            result.Description = "addr=" + std::to_string(FoundFlaggedAtAddress);
        }

        return result;
    }
};