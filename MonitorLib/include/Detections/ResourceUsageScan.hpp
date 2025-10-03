// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../ProcessHelper.hpp"
#include "../EncryptedStr.hpp"
#include "../StrHelper.hpp"
#include <mutex>
#include <psapi.h>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <numeric>
#include <string>
#include <regex>
#include <pdh.h>
#include <pdhmsg.h>
#include <iomanip>

#pragma comment(lib, "Pdh.lib")  //performance counters via powershell to track gpu usage per PID
#pragma comment(lib, "Psapi.lib")

struct GpuUsage
{
    DWORD pid = 0;
    double percent = 0.0f;  // summed over all engines
    std::wstring name; // optional process name

    bool operator ==(const GpuUsage& other) const noexcept
    {
        return (this->pid == other.pid && name == other.name);
    }
};

class PdhGpuSampler //WARNING: AI-generated class - while the scan appears to work fine, there may be hidden or unknown bugs associated with this class
{
public:
    PdhGpuSampler() 
    {
        PDH_STATUS s = PdhOpenQueryW(nullptr, 0, &q_);
        if (s != ERROR_SUCCESS) 
            throw std::runtime_error("PdhOpenQueryW failed");

        // Use the ENGLISH-name API to avoid localization issues.
        // Path: \\GPU Engine(*)\\Utilization Percentage
        s = PdhAddEnglishCounterW(q_, L"\\GPU Engine(*)\\Utilization Percentage", 0, &ctr_);
        if (s != ERROR_SUCCESS) 
            throw std::runtime_error("PdhAddEnglishCounterW failed");

        // First collection initializes the query
        PdhCollectQueryData(q_);
        Sleep(200); // small settle; PDH needs two samples for cooked values
    }

    ~PdhGpuSampler() 
    {
        if (q_) 
            PdhCloseQuery(q_);
    }

    // If you want only 3D/Compute engines, set filter3DCompute = true
    std::vector<GpuUsage> Sample(bool filter3DCompute = false) 
    {
        PDH_STATUS s = PdhCollectQueryData(q_);

        if (s != ERROR_SUCCESS) 
            return {};

        DWORD bufSize = 0, itemCount = 0;
        
        s = PdhGetFormattedCounterArrayW(ctr_, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &bufSize, &itemCount, nullptr);
        
        if (s != PDH_MORE_DATA) 
            return {};

        std::vector<BYTE> buf(bufSize);
        
        auto* arr = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buf.data());
        
        s = PdhGetFormattedCounterArrayW(ctr_, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, &bufSize, &itemCount, arr);
        
        if (s != ERROR_SUCCESS) 
            return {};

        std::unordered_map<DWORD, double> sumByPid;

        for (DWORD i = 0; i < itemCount; ++i) 
        {
            const wchar_t* inst = arr[i].szName; // e.g., "pid_1234_engtype_3D_0"
            double val = arr[i].FmtValue.doubleValue;
        
            DWORD pid = 0; // Extract pid
            const wchar_t* p = wcsstr(inst, L"pid_");
            if (!p) 
                continue;

            p += 4;

            while (*p >= L'0' && *p <= L'9') 
            {
                pid = pid * 10 + (*p - L'0');
                ++p;
            }

            if (filter3DCompute) 
            {
                // keep only 3D/Compute engines
                if (!wcsstr(inst, L"engtype_3D") && !wcsstr(inst, L"engtype_Compute"))
                    continue;
            }

            sumByPid[pid] += val; // sum utilization across engines
        }

        std::vector<GpuUsage> out;
        out.reserve(sumByPid.size());
        for (auto& kv : sumByPid) 
        {
            GpuUsage g{ kv.first, kv.second, ProcessHelper::GetProcessName(kv.first) };
            out.push_back(std::move(g));
        }

        // sort high to low
        std::sort(out.begin(), out.end(), [](const GpuUsage& a, const GpuUsage& b) { return a.percent > b.percent; });
        return out;
    }

private:
    PDH_HQUERY q_{};
    PDH_HCOUNTER ctr_{};
};

class ResourceUsageScan : public IDetector
{
private:
    enum ResourceType
    {
        None,
        GPU,
        CPU,
        Memory
    };

    struct Sample 
    { 
        ResourceType type = ResourceType::None;
        std::chrono::steady_clock::time_point t; 
        unsigned int totalPct = 0; 

        std::vector<GpuUsage> UsagePerPID;

        bool operator ==(const Sample& other) const noexcept
        {
            return (this->t == other.t);
        }
    };
    
    std::vector<Sample> history;           // sliding window of recent GPU totals
    std::mutex HistoryLock;

    std::mutex RunMutex;

    size_t secondsToTestCPU = 10;
    size_t secondsToTestGPU = 10;
    
    unsigned int cpuThreshold = 90;
    unsigned int gpuThreshold = 85;
    
    ULONGLONG prevTime = 0;

    std::atomic<bool> jobRunning{ false };
    std::thread jobThread;
    std::mutex jobMx;
    bool hasResult{ false };
    DetectionResult pendingResult{};
    std::atomic<bool> stopRequested{ false };

    float GetMemoryUsage()
    {
        MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
        if (GlobalMemoryStatusEx(&memStatus))
            return (float)memStatus.dwMemoryLoad;
        return 0.0f;
    }

   
    // CPU% (system) over delta window. Call twice across runs.
    bool GetSystemCpuPercent(double& outPct)
    {
        static FILETIME s_idlePrev{}, s_kernPrev{}, s_userPrev{};
        FILETIME idle, kern, user;
        if (!GetSystemTimes(&idle, &kern, &user)) return false;

        ULONGLONG idleNow = *(ULONGLONG*)&idle;
        ULONGLONG kernNow = *(ULONGLONG*)&kern;
        ULONGLONG userNow = *(ULONGLONG*)&user;

        if (s_idlePrev.dwLowDateTime == 0 && s_idlePrev.dwHighDateTime == 0) 
        {
            s_idlePrev = idle; s_kernPrev = kern; s_userPrev = user;
            outPct = 0.0; // first call has no delta
            return true;
        }

        ULONGLONG idleDiff = idleNow - *(ULONGLONG*)&s_idlePrev;
        ULONGLONG kernDiff = kernNow - *(ULONGLONG*)&s_kernPrev;
        ULONGLONG userDiff = userNow - *(ULONGLONG*)&s_userPrev;
        ULONGLONG sys = kernDiff + userDiff;
        if (sys == 0) 
        { 
            outPct = 0.0; return true; 
        }

        double busy = (double)(sys - idleDiff);
        outPct = (busy / (double)sys) * 100.0;

        s_idlePrev = idle; s_kernPrev = kern; s_userPrev = user;
        return true;
    }

public:
    ResourceUsageScan() = default;

    ~ResourceUsageScan() override 
    {
        stopRequested = true;

        if (jobThread.joinable())  // if a job is running, wait for it to finish
            jobThread.join();
    }

    double GetGPUAverageUsageForPid(__in const uint32_t pid)
    {
        std::lock_guard<std::mutex> lock(HistoryLock);
       
        double average = 0;
        uint32_t count = 0;

        for (const auto& slice : history)
        {
            for (int i = 0; i < slice.UsagePerPID.size(); i++)
            {
                if (slice.UsagePerPID[i].pid == pid)
                {
                    average += slice.UsagePerPID[i].percent;
                    count++;
                }
            }          
        }

        if (count != 0)
        {
            average /= static_cast<double>(count);
        }

        return average;
    }

    ResourceUsageScan(const DetectionRule& rule) 
    { 
        Deserialize(rule);

        if (rule.Artifacts.empty())
            return;

        std::regex re(R"(^(CPU|GPU)\s+(\d+)%\s+(\d+)s$)");
        std::smatch match;

        for (const std::string& artifact : rule.Artifacts)
        {
            if (std::regex_match(artifact, match, re))
            {
                std::string type = match[1];
                int percent = std::stoi(match[2]);
                int seconds = std::stoi(match[3]);

                if (type == "GPU")
                {
                    secondsToTestGPU = seconds;
                    gpuThreshold = percent;
                }
                else if (type == "CPU")
                {
                    secondsToTestCPU = seconds;
                    cpuThreshold = percent;
                }
                else if (type == "Memory") //not yet implemented
                {

                }

            }
        }
    }

    // start worker if none is running
    void startAveragingJob() 
    {
        bool expected = false;
        if (!jobRunning.compare_exchange_strong(expected, true)) 
            return; // already running

        // (Re)launch worker
        if (jobThread.joinable()) 
            jobThread.join();

        jobThread = std::thread([this] 
            {
            DetectionResult result{};
            result.Flag = DetectionFlags::NONE;

            try 
            {
                const int secs = static_cast<int>(this->secondsToTestGPU);
                PdhGpuSampler sampler;  // your PDH wrapper
                // Per-PID accumulators over window
                std::unordered_map<uint32_t, double> sumPct;
                std::unordered_map<uint32_t, int> cnt;

                for (int i = 0; i < secs && !stopRequested.load(); ++i) 
                {
                    auto v = sampler.Sample(true); /*filter3DCompute=*/

                    // record instantaneous per-PID and push history slice
                    {
                        Sample s;
                        s.type = ResourceType::GPU;
                        s.t = std::chrono::steady_clock::now();
                        s.totalPct = 0;
                        s.UsagePerPID = v;

                        for (auto& g : v) 
                        {
                            sumPct[g.pid] += g.percent;
                            cnt[g.pid] += 1;
                            s.totalPct += static_cast<unsigned int>(g.percent);
                        }

                        std::lock_guard<std::mutex> lk(HistoryLock);
                        history.push_back(std::move(s));
                        if (history.size() > 30) history.erase(history.begin());
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                // Evaluate thresholds after window
                // GPU: flag the *worst* PID’s average
                uint32_t worstPidGPU = 0;
                double worstAvgGPU = 0.0;
                for (auto& kv : sumPct) 
                {
                    double avg = kv.second / std::max(1, cnt[kv.first]);
                    if (avg > worstAvgGPU) 
                    { 
                        worstAvgGPU = avg; 
                        worstPidGPU = kv.first; 
                    }
                }
                if (worstAvgGPU >= gpuThreshold) 
                {
                    result.Flag = DetectionFlags::HIGH_GPU_USAGE;
                    result.ProcessId = worstPidGPU;
                    result.Description = "GPU=" + std::to_string(static_cast<int>(worstAvgGPU));
#ifdef _LOGGING_ENABLED
                    std::string msg = "GPU Threshold met! Highest Usage pid = " + std::to_string(worstPidGPU) + " (" + StrHelper::WStringToString(ProcessHelper::GetProcessName(worstPidGPU)) + "\n";
                    OutputDebugStringA(msg.c_str());
#endif
                }

                // CPU (system-wide) over same period (EMA style is better; here: last sample)
                double cpuPct = 0.0;
                (void)GetSystemCpuPercent(cpuPct); // call once to init deltas
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                (void)GetSystemCpuPercent(cpuPct);
                if (cpuPct >= cpuThreshold && result.Flag == DetectionFlags::NONE) 
                {
                    result.Flag = DetectionFlags::HIGH_CPU_USAGE;
                    result.ProcessId = 0; // system
                    result.Description = "CPU=" + std::to_string(static_cast<int>(cpuPct));
                }

            }
            catch (const std::exception& e) 
            {
#ifdef _LOGGING_ENABLED
                OutputDebugStringA(("ResourceUsageScan job exception: " + std::string(e.what()) + "\n").c_str());
#endif
                result.Flag = DetectionFlags::EXECUTION_ERROR;
            }

            // publish result
            {
                std::lock_guard<std::mutex> lk(jobMx);
                pendingResult = result;
                hasResult = true;
            }
            jobRunning = false;
        });
    }

    DetectionResult Run() override 
    {    
        DetectionResult result{};
        result.Flag = DetectionFlags::NONE;
        if (!Enabled()) 
        {
            result.Flag = DetectionFlags::NONE;
            return {};
        }

        // Fast path: if we already have a finished result, return it now
        {
            std::lock_guard<std::mutex> lk(jobMx);
            if (hasResult) 
            {
                result = pendingResult;
                hasResult = false;
                // optionally: immediately start next job so windows overlap seamlessly
                startAveragingJob();
                return result;
            }
        }

        // No result yet: ensure a job is running; return quickly
        startAveragingJob();
        return result; // NONE (no block). Your scheduler will call again later.
    }
};