// IDetector.hpp 
//By Alsch092 @ Github
#pragma once
#include "DetectionResult.hpp"
#include <atomic>

enum ScanIds
{
    Uninitialized = 0,
    ByteSignature,
    ProcessHandles,
    FileHash,
    ManualMap,
    Hypervisor,
    ProcessIsAdmin,
    ProcessString,
    SecureBoot,
    DriverSignatureEnforcement,
    HVCI,
    IATModified,
    UnsignedLoadedModule,
    ProcessCommandLine,
    ResourceUsage, //GPU, memory usage 
    NetworkConnection,
    LoadedDrivers,
    ProcessEnumerator,

    Custom = 100, //user-supplied rule, use a number greater than 100 in your own
};

struct PROCESS_DATA
{
    std::wstring baseName;
    std::wstring path; //full path

    uint32_t pid = 0;

    uint32_t fileHash = 0; //crc32 of file on disk
    uint64_t fileSize = 0;

    bool bIsSigned = false;
    bool bIsWoW64 = false;
    bool bCanObtainHandle = false;

    uint32_t GPUAllocation = 0;
    uint32_t MemoryAllocation = 0;

    //std::vector<MODULE_DATA> loadedModules;

    std::vector<uint32_t> FlaggedByScans;

    bool operator ==(const PROCESS_DATA& other) const noexcept
    {
        return (path == other.path && pid == other.pid);
    }
};

struct DetectionRule //can we merge this into IDetector somehow?
{
    bool bEnabled = false;

    ScanIds id = Uninitialized; //dictates the type of class which will be created based on the rule (BytePatterScan, OpenHandleScan, etc)

    std::string Label;

    uint8_t Severity = 1; //1 = Info, 2 = Warning, 3 = Critical

    bool bIsProcessScan = false;
    bool bIsOneTimeScan = false;
    bool bIsSelfProcessScan = false;
    bool bIsSystemConfigScan = false; //scans such as secure boot, DSE check, HVCI, etc.
    bool bForceShutdownOnFlag = false;
    bool bTerminateOffendingProcess = false;
    bool bContinuousScan = false;

    std::vector<std::string> Names;
    std::vector<std::string> Artifacts; //process names, byte signatures, etc

    bool operator ==(const DetectionRule& other) const noexcept
    {
        return  this->id == other.id;
    }
};

class IDetector 
{
private:
    std::atomic<bool> bEnabled = false;

    ScanIds id = Uninitialized;

    uint8_t Severity = 0;

    std::string label;

    bool bIsProcessScan = false; //these are not marked as atomic because they generally should not be changed after set
    bool bIsSelfScan = false;
    bool bIsSystemConfigScan = false;
    bool bIsOnetimeCheck = false;
    bool bForceShutdownOnFlag = false;
    bool bTerminateOffendingProcess = false;
    bool bContinuousScan = false;

protected:
    uint32_t ProcessId = 0;
    std::atomic<uint32_t> RunCount = 0;
    uint8_t LastError = 0;

public:
    virtual ~IDetector() = default;
    virtual DetectionResult Run() = 0;

    bool IsOneTimeCheck() const noexcept  { return this->bIsOnetimeCheck; }
    bool DidOneTimeCheck() const noexcept { return RunCount > 0;  }

    bool IsSelfScan() const noexcept { return this->bIsSelfScan; }
    bool IsProcessScan() const noexcept { return this->bIsProcessScan; }
    bool ShouldShutdownOnFlag() const noexcept { return this->bForceShutdownOnFlag; }

    ScanIds GetId() const noexcept { return this->id; }
    void SetId(const ScanIds Id) noexcept { this->id = Id; }

    void SetIsProcessScan(const bool IsProcScan) noexcept  { this->bIsProcessScan = IsProcScan; }

    bool IsSystemConfigScan() const noexcept { return this->bIsSystemConfigScan; }
    void SetIsSystemConfigScan(const bool IsSystemConfigScan) noexcept { this->bIsSystemConfigScan = IsSystemConfigScan; }

    bool IsContinuousScan() const noexcept { return this->bContinuousScan; }

    bool ShouldTerminateOffendingProcess() const noexcept { return this->bTerminateOffendingProcess; }

    void Deserialize(const DetectionRule& rule)
    {
        this->SetEnabled(rule.bEnabled);
        this->SetId(rule.id);
        this->SetLabel(rule.Label);
        this->SetSeverity(rule.Severity);
        this->SetIsProcessScan(rule.bIsProcessScan);
        this->SetSelfScan(rule.bIsSelfProcessScan);
        this->SetIsProcessScan(rule.bIsProcessScan);
        this->SetOneShotCheck(rule.bIsOneTimeScan);
        this->SetIsSystemConfigScan(rule.bIsSystemConfigScan);
        this->SetShutdownOnFlag(rule.bForceShutdownOnFlag);
        this->SetTerminateOffendingProcess(rule.bTerminateOffendingProcess);
        this->SetContinuousScan(rule.bContinuousScan);
    }

    bool Enabled() const noexcept
    {
        return this->bEnabled.load();
    }

    void SetEnabled(const bool enabled) noexcept
    {
        this->bEnabled.store(enabled);
    }

    void SetTargetProcess(const uint32_t pid) noexcept
    {
        if (pid == 0 || pid == 4)
            return;

        this->ProcessId = pid;
    }

    void SetSeverity(const uint8_t Severity) noexcept
    {
        this->Severity = Severity;
    }

    void SetLabel(const std::string& label) noexcept
    {
        if(!label.empty())
            this->label = label;
    }

    void SetOneShotCheck(const bool isOneTimeChecked) noexcept
    {
        this->bIsOnetimeCheck = isOneTimeChecked;
    }

    void SetLastError(const uint8_t err) noexcept
    {
        this->LastError = err;
    }

    void SetSelfScan(const bool isSelfScan) noexcept 
    { 
        this->bIsSelfScan = isSelfScan; 
    }

    void SetShutdownOnFlag(const bool bShutdownOnFlag) noexcept 
    { 
        this->bForceShutdownOnFlag = bShutdownOnFlag; 
    }

    void SetTerminateOffendingProcess(const bool bTerminate) noexcept
    {
        this->bTerminateOffendingProcess = bTerminate;
    }

    void SetContinuousScan(const bool bIsContinuous) noexcept
    {
        this->bContinuousScan = bIsContinuous;
    }

};