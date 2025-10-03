// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../ProcessHelper.hpp"
#include "../StrHelper.hpp"
#include "../Authenticode.hpp"
#include <mutex>
#include <unordered_set>

class UnsignedLoadedModulesScan : public IDetector //one-shot check
{
private:
    std::list<std::wstring> UnsignedLoadedModules;
    std::unordered_set<std::wstring> WhitelistedModules;
    std::unordered_set<std::wstring> CheckedUnsignedModules; // cache of known unsigned
    std::unordered_set<std::wstring> CheckedSignedModules;   // cache of known signed

    std::mutex ListMutex;

public:
    UnsignedLoadedModulesScan() = default;
    ~UnsignedLoadedModulesScan() = default;

    UnsignedLoadedModulesScan(__in const DetectionRule& rule)
    {
        this->Deserialize(rule);

        //std::wstring procPath = ProcessHelper::GetProcessPathByPID(GetCurrentProcessId());
        //std::wstring procDir = procPath.substr(0, procPath.find_last_of('\\'));
        //std::wstring enginePath = procDir + L"\\DetectionEngine.dll";

        // whitelist current module
        //AddToWhitelist(StrHelper::ToLower(ProcessHelper::GetProcessPathByPID(GetCurrentProcessId())));
        //AddToWhitelist(StrHelper::ToLower(enginePath));
    }

    void AddToWhitelist(__in const std::wstring& whitelistedModule)
    {
        std::lock_guard<std::mutex> lock(ListMutex);

        if(WhitelistedModules.count(whitelistedModule) == 0)
            WhitelistedModules.insert(whitelistedModule);
    }

    DetectionResult Run() override
    {
        if (!this->Enabled())
            return {};

        DetectionResult result;
        result.Flag = DetectionFlags::NONE;
        this->RunCount++;

        bool bFoundUnsignedLoadedModule = false;

        auto modules = ProcessHelper::GetLoadedModules();

        if (modules.empty())
        {
            result.Flag = DetectionFlags::EXECUTION_ERROR;
            return result;
        }

        for (const auto& module : modules)
        {
            std::wstring modNameLower = StrHelper::ToLower(module.name);

            {
                std::lock_guard<std::mutex> lock(ListMutex);
                if (WhitelistedModules.count(modNameLower))
                    continue;
                if (CheckedSignedModules.count(modNameLower))
                    continue; // already verified as signed
                if (CheckedUnsignedModules.count(modNameLower))
                    continue; // already flagged as unsigned
            }

            // expensive check only if not in cache
            if (!Authenticode::HasSignature(module.name.c_str(), TRUE))
            {
                std::lock_guard<std::mutex> lock(ListMutex);
                if (!CheckedUnsignedModules.count(modNameLower))
                {
                    CheckedUnsignedModules.insert(modNameLower);
                    UnsignedLoadedModules.push_back(modNameLower);
                    bFoundUnsignedLoadedModule = true;
#ifdef _LOGGING_ENABLED
                    std::wstring msg = L"Found unsigned loaded module: " + modNameLower + L"\n";
                    OutputDebugStringW(msg.c_str());
#endif
                }
            }
            else
            {
                std::lock_guard<std::mutex> lock(ListMutex);
                CheckedSignedModules.insert(modNameLower);
            }
        }

        if (bFoundUnsignedLoadedModule)
        {
            result.Flag = DetectionFlags::LOADED_UNSIGNED_MODULE;
            result.ProcessId = GetCurrentProcessId();

            if (!UnsignedLoadedModules.empty())
                result.Description = StrHelper::WStringToString(UnsignedLoadedModules.front());
        }

        return result;
    }
};