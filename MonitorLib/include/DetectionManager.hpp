// Made by AlSch092 @ GitHub
#define _TARGET_OS_WINDOWS

#ifndef _TARGET_OS_WINDOWS
#define _TARGET_OS_LINUX
#endif

#pragma once
#include "IDetector.hpp"
#include "EncryptedStr.hpp"
#include "Telemetry.hpp"
#include <vector>
#include <memory>
#include <list>
#include <queue>
#include <iostream>
#include <mutex>
#include <atomic>

/*
 * @brief PIMPL idiom class for .lib usage
 *
 * @details Signatures should be downloaded from outside this class, then registered using the `Register` function
 *
 * @details WMI process creation callbacks are used by this class, and detections are run each time a new process is created
 * @details Detections can either be process-based (byte scans) or non-process related (such as secure boot checks, etc)
 */
class DetectionManager final
{
private:
    struct Impl;
    Impl* pImpl;

    std::atomic<bool> bScheduledShutdown = false;
    std::atomic<bool> bLogTelemetry = true;

    std::list<std::string> DetectionsRepositoryLocations;

    void RegisterRule(__in const DetectionRule& dr);

    std::vector<DetectionResult> Detected;
    std::mutex DetectedListMutex;

    std::vector<std::shared_ptr<IDetector>> Detectors;
    std::mutex DetectorListMutex;

    void AddDetected(const DetectionResult& dr)
    {
        std::lock_guard<std::mutex> lock(this->DetectedListMutex);

        if (std::find(this->Detected.begin(), this->Detected.end(), dr) == this->Detected.end())
            this->Detected.push_back(dr);
    }

    std::unique_ptr<Telemetry> TelemetryManager = nullptr;

    std::mutex SuspiciousProcessMutex;

public:

    explicit DetectionManager(const bool bUsingTelemetry, const std::string& TelemetryEndpoint,  const bool bMonitorProcessCreation, const bool bGetDllNotifications, const bool bCheckUnsignedModules);
    ~DetectionManager();

    DetectionManager(DetectionManager&&) = delete;
    DetectionManager& operator=(DetectionManager&&) noexcept = default;
    DetectionManager(const DetectionManager&) = delete;
    DetectionManager& operator=(const DetectionManager&) = delete;

    bool StartDetections();
    bool FetchDetectionRules(__in const std::string& url, __in const bool bShouldDecrypt);

    void ScheduleShutdown(const bool bShouldShutdown) { this->bScheduledShutdown.store(bShouldShutdown); }
    bool IsShutdownScheduled() const noexcept { return this->bScheduledShutdown.load(); }

    void UseTelemetry(const bool bUseTelemetry) noexcept { this->bLogTelemetry.store(bUseTelemetry); }
    bool UsingTelemetry() const noexcept { return this->bLogTelemetry.load(); }

    void AddDetectionsRepository(__in const std::string& location) 
    { 
        if (std::find(DetectionsRepositoryLocations.begin(), DetectionsRepositoryLocations.end(), location) == DetectionsRepositoryLocations.end())
            DetectionsRepositoryLocations.push_back(location);
    }

    void Register(std::shared_ptr<IDetector> detector) 
    { 
        std::lock_guard<std::mutex> lock(this->DetectorListMutex); 
        Detectors.push_back(std::move(detector)); 
    }

    std::shared_ptr<IDetector> GetDetectorWithId(const ScanIds id)
    {
       //std::lock_guard<std::mutex> lock(this->DetectorListMutex);

        auto it = std::find_if(Detectors.begin(), Detectors.end(), [id](const std::shared_ptr<IDetector>& detector) { return (detector && id == detector.get()->GetId()); });
        
        if (it != Detectors.end())
            return std::shared_ptr<IDetector>(it->get(), [](IDetector*) {}); // non-owning shared_ptr

        return nullptr;
    }

    /**
     * @brief Returns a copy of the detected fragments list
     * @return  std::vector<DetectionResult> vector of DetectionReuslt
     */
    std::vector<DetectionResult> GetDetectedFragments() 
    { 
        std::vector<DetectionResult> DetectedFragmentsCpy;
        {
            std::lock_guard<std::mutex> lock(this->DetectedListMutex);
            DetectedFragmentsCpy = this->Detected;
        }

        return  DetectedFragmentsCpy;
    }

    void PrintDetectedFragments()
    {
        std::lock_guard<std::mutex> lock(this->DetectedListMutex);

        for (const auto& fragment : this->Detected)
        {
            std::cout << "Flag: " << fragment.Flag << ", description: " << fragment.Description << " , processId: " << fragment.ProcessId << std::endl;
        }
    }

    Telemetry* GetTelemetryManager() const noexcept { return this->TelemetryManager.get(); }

    std::list<PROCESS_DATA> GetSuspiciousProcesses();
    void AddSuspiciousProcess(__in const uint32_t pid, __in const std::wstring& path, __in const ScanIds flaggedByScan);
    void AddSuspiciousProcess(__in const PROCESS_DATA& pd);
    static void FillProcessInfo(__in PROCESS_DATA& p);
};