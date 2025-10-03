// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../ProcessHelper.hpp"
#include "../StrHelper.hpp"
#include "../EncryptedStr.hpp"
#include <vector>
#include <string>
#include <mutex>
#include <memory>

struct BytePattern
{
    std::vector<uint8_t> Pattern;
    std::string Name; //process or module name - optional

    BytePattern(std::vector<uint8_t> p, std::string name) : Pattern(p), Name(name) {}
};

/**
* @brief The ByteSignatureScan scans the `.text` section of a running process for a particular byte pattern, which supports wildcard bytes ('?' = wildcard)
*
*/
class ByteSignatureScan : public IDetector 
{
private:
    std::vector<BytePattern> PatternList;
    std::mutex ListMutex;
    bool bIsFixedTargetProcessId = false;

public:
    ByteSignatureScan() = default;
    ~ByteSignatureScan() = default;

    ByteSignatureScan(__in const ScanIds id)
    {
        this->SetId(id);
    }

    ByteSignatureScan(__in const DetectionRule& rule)
    {
        this->Deserialize(rule);

        int count = 0;

        for (const auto& pattern : rule.Artifacts)
        {
            std::vector<uint8_t> bytes = StrHelper::HexStringToBytes(pattern);

            if (!bytes.empty())
            {
                std::string name;
                if (!rule.Names.at(count).empty())
                    name = rule.Names.at(count++);

                this->AddPattern(BytePattern(std::move(bytes), name));
            }
        }
    }

    void SetFixedProcessId(const bool bFixProcessId) noexcept { this->bIsFixedTargetProcessId = bFixProcessId; }
    void SetFixedProcessId(const uint32_t pid) noexcept { this->bIsFixedTargetProcessId = true; this->ProcessId = pid; }

    void SetTargetProcess(const uint32_t pid)
    {
        if (this->bIsFixedTargetProcessId)
            return;

        this->ProcessId = pid;
    }

    DetectionResult Run() override
    {
        if (!this->Enabled())
            return {};

        DetectionResult result;
        result.Flag = DetectionFlags::NONE;

        constexpr auto textEnc = XorStr::make_encrypted(".text");

        std::lock_guard<std::mutex> lock(ListMutex);
        for (const auto& pattern : PatternList)
        {
            if (ProcessHasPattern(pattern, textEnc.decrypt().c_str()))
            {
                result.Flag = DetectionFlags::BLACKLISTED_BYTE_PATTERN;
                result.ProcessId = this->ProcessId;
                break;
            }         
        }

        this->RunCount++;

        return result;
    }

    void SetProcess(uint32_t ProcessId)
    {
        this->ProcessId = ProcessId;
    }

    void AddPattern(BytePattern bp)
    {
        std::lock_guard<std::mutex> lock(ListMutex);
        this->PatternList.push_back(bp);
    }

    bool ProcessHasPattern(__in const BytePattern& bp, __in const char* section)
    {
        if (this->ProcessId <= 4 || section == nullptr)
            return false;

        HandleGuard hProcess = HandleGuard(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId));

        if (!hProcess.isValid())
            return false;

        int sectionReadSize = 0;
        uint8_t* textSectionBytes = nullptr;

#ifdef _M_X64
        //64-bit AC: can read both x64 and WoW64 targets
        textSectionBytes = ProcessHelper::ReadRemoteSection(ProcessId, section, sectionReadSize);
#else
        if (ProcessHelper::IsProcessWoW64(hProcess))
        {
            //target is WoW64 (32-bit)
            textSectionBytes = ProcessHelper::ReadRemoteSection(ProcessId, section, sectionReadSize);
        }
        else
        {
            //target is 64-bit → need WoW64 helper
            textSectionBytes = ProcessHelper::ReadRemoteSectionWoW64(ProcessId, section, sectionReadSize);
        }
#endif

        if (textSectionBytes == nullptr)
            return false;

        bool bFullPatternMatches = false;

        size_t patternSize = bp.Pattern.size();

        if (textSectionBytes && sectionReadSize >= patternSize)
        {
            const uint8_t* pattern = bp.Pattern.data();
            
            for (size_t i = 0; i <= sectionReadSize - patternSize; ++i)
            {
                for (int j = 0; j < patternSize; j++)
                {      
                    if (textSectionBytes[i + j] == pattern[j] || pattern[j] == '?')
                    {
                        bFullPatternMatches = true;
                    }
                    else
                    {
                        bFullPatternMatches = false;
                        break;
                    }
                }

                if (bFullPatternMatches)
                {
#ifdef _LOGGING_ENABLED
                    wprintf(L"Found blacklisted byte pattern in process %d at offset %zu\n", ProcessId, i);
#endif
                    break;
                }

            }
        }

        if (textSectionBytes != nullptr)
            delete[] textSectionBytes;

        return bFullPatternMatches;
    }
};