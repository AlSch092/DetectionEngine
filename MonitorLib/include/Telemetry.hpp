//By Alsch092 @ Github
#pragma once
#include "json/json.hpp"
#include "../../HttpLib/HttpLib.hpp"
#include "CircularBuffer.hpp"
#include "EventLog.hpp"
#include "EncryptedStr.hpp"
#include <mutex>
#include <atomic>
#include <vector>
#include <chrono>
#include <queue>

using json = nlohmann::json;

struct TelemetryEvent
{
    enum Action
    {
        None,
        ProcessOpen,
        ProcessClose,
        ModuleLoad,
        ModuleUnload,
        SelfShutdown,
        Heartbeat,
        Flag,
        SuspiciousProgram,
        TerminatedProcess,
        ProgramError,
    };

    uint32_t EventId = 0; 
    std::string ClientId = 0;
    Action action = Action::None;
    uint32_t FlagId = 0;
    uint32_t processId = 0;
    std::string processPath;
    uint64_t timestamp = 0;

    TelemetryEvent() = default;

    TelemetryEvent(const uint32_t EventId, const std::string ClientId, const Action action, const uint32_t processId, const std::string& processPath, const uint32_t FlagId)
        : EventId(EventId), ClientId(ClientId), action(action), processId(processId), processPath(processPath), FlagId(FlagId), timestamp(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()))
    {
    }

    bool operator ==(const TelemetryEvent& other) const noexcept
    {
        return  (this->EventId == other.EventId && this->processId == other.processId && this->action == other.action);
    }
};


/*
    Telemetry - A singleton class that logs events to a server endpoint.
    It uses a separate thread to send data to the server asynchronously.

    Purely for telemetry, this class does not perform any security checks or validations.
    You should call this as `Telemetry::GetInstance().LogEvent(event);` from your game after setting your server endpoint via `SetEndpoint(string url)`
*/
class Telemetry
{
    enum VerbosityLevel
    {
        Zero,
        Low,
        Medium,
        Maximum
    };

public:
    Telemetry();
    ~Telemetry();

    void Start();

    void SetEndpoint(const std::string& endpoint);
    static uint64_t GetUnixTimestampMs();

    void SetClientId(__in const std::string cid) noexcept { this->ClientId = cid; }
    const std::string GetClientId() const noexcept { return this->ClientId; }

    uint32_t FetchAddEventId() noexcept { return this->CurrentEventId.fetch_add(1); }

    VerbosityLevel GetLoggingGranularity() const noexcept { return this->LoggingLevel; }
    void SetGranularityLevel(const VerbosityLevel gl) noexcept  { this->LoggingLevel = gl; }

    /**
     * @brief places a game event into the queue to be sent to the server
     *
     * @param `events` GameEvent objects containing the event type, timestamp, and details. One or more objects can be passed in one call
     *
     * @return void
     *
     * @usage
     * 	TelemetryManager->LogEvent(TelemetryEvent(GetTelemetryManager()->FetchAddEventId(),"client123",TelemetryEvent::Action::Flag,pid,StrHelper::WStringToString(ProcessHelper::GetProcessPathByPID(pid)),FlagId));
     */
    template <typename... Events>
    void LogEvent(Events&&... events)  //multiple events can be passed into this routine
    {
        std::lock_guard<std::mutex> lock(mtx);

        // push each arg, in order
        using expander = int[];
        (void)expander 
        {
            0, ((void)eventQueue.push(std::forward<Events>(events)), 0)...
        };
    }

private:
    std::mutex mtx;
    std::thread workerThread;
    std::queue<TelemetryEvent> eventQueue;
    std::string ServerEndpoint;
    std::atomic<bool> running = false;

    bool SendDataToServer();

    std::atomic<uint32_t> CurrentEventId = 0; //+1 for each event send

    std::string ClientId;

    VerbosityLevel LoggingLevel = VerbosityLevel::Maximum; //different verbosity levels haven't been implemented yet
};
