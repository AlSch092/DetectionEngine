//By Alsch092 @ Github
#include "../include/Telemetry.hpp"
#include "../include/StrHelper.hpp"

void to_json(json& j, const TelemetryEvent& TE)
{
	j = json{
		{"event_id", TE.EventId},
		{"client_id", TE.ClientId},
		{"action", TE.action},
		{"flag_id", TE.FlagId},
		{"process_id", TE.processId},
		{"process_path", TE.processPath.empty() ? nullptr : json(TE.processPath)},
		{"timestamp", TE.timestamp}
	};
}

/**
 * @brief class object constructor
 *
 * @details This constructor should not directly be used, instead use `EventLogger::GetInstance()` to get the singleton instance.
 *           A worker thread is created which calls `SendDataToServer` if the event queue is not empty.
 *
 * @return newly allocated class object
 *
 * @usage  Do not use!
 */
Telemetry::Telemetry()
{
	running.store(true);

	if (!this->ServerEndpoint.empty())
		Start();

	//    try
	//    {
	//        EventBufferManager = std::make_unique<MPSC<TelemetryEvent, 128>>();
	//    }
	//    catch (const std::bad_alloc& ex)
	//    {
	//        //fall back to event queue
	//#ifdef _LOGGING_ENABLED
	//        std::string msg = "Failed to allocate ring buffer for telemetry: " + std::string(ex.what()) + "\n";
	//        OutputDebugStringA(msg.c_str());
	//#endif
	//    }
}

void Telemetry::Start()
{
	running.store(true);

	if (this->ClientId.empty())
	{
		this->ClientId = GenerateClientId();
	}

	workerThread = std::thread([this]()
		{
			while (running.load())
			{
				{
					bool bQueueEmpty = false;
					{
						std::lock_guard<std::mutex> lock(mtx);
						bQueueEmpty = eventQueue.empty();
					}

					if (!this->ClientId.empty() && !bQueueEmpty)
					{
						if (!SendDataToServer()) //failed after 5 re-tries  -> Fallback to using event logger?
						{
#ifdef _LOGGING_ENABLED
							OutputDebugStringA("Could not push event data after multiple tries. Network may be down, or server is not available.\n");
#endif
							constexpr auto msg = XorStr::make_encrypted(L"Could not push event data after multiple tries. Network may be down, or server is not available.");
							EventLog ev(L"DetectionEngine");
							ev.error(msg.decrypt().c_str());
						}
					}
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		});
}

/**
 * @brief Cleans up resources used by the class object
 *
 * @return None
 *
 * @usage
 * delete eventLogger;
 */
Telemetry::~Telemetry()
{
	running.store(false);
	if (workerThread.joinable())
		workerThread.join();
}

/**
 * @brief Pushes the queue of events to the endpoint server
 * @details  if failure occurs, will re-try 5 times until success
 * @return true/false, indicating successful network request
 * @usage  Should not be directly called. A worker thread is created in the class constructor to handle data pushes
 */
bool Telemetry::SendDataToServer()
{
	if (this->ServerEndpoint.empty())
	{
#ifdef _LOGGING_ENABLED
		printf("Server endpoint is not set. Cannot send event data.\n");
#endif
		return false;
	}

	static constexpr size_t MAX_BATCH = 50;          // max events per POST
	static constexpr size_t MAX_BYTES = 512 * 1024;   // cap payload ~512 KB
	static constexpr int    MAX_RETRIES = 5;
	static constexpr int    BASE_BACKOFF_MS = 200;

	//drain a batch from the queue
	std::vector<TelemetryEvent> batch;
	batch.reserve(128);

	size_t approxBytes = 2; // [] brackets
	{
		std::lock_guard<std::mutex> lock(mtx);
		while (!eventQueue.empty() && batch.size() < MAX_BATCH)
		{
			const TelemetryEvent& ev = eventQueue.front();
			if (ev.action == TelemetryEvent::Action::None)
			{
				eventQueue.pop();
				continue;
			}

			nlohmann::json j = ev;
			std::string s = j.dump(); // no pretty-print for size
			size_t nextSize = approxBytes + (batch.empty() ? 0 : 1) + s.size(); // + comma

			if (nextSize > MAX_BYTES && !batch.empty())
			{
				// stop here, keep this event for next round
				break;
			}

			batch.push_back(ev);
			approxBytes = nextSize;
			eventQueue.pop();
		}
	}

	if (batch.empty())
	{
		return false; // nothing to send
	}

	auto requeue_preserve_order = [&](const std::vector<TelemetryEvent>& toReturn)
		{
			// push back in reverse so the earliest pops first next time
			std::lock_guard<std::mutex> lock(mtx);
			for (auto it = toReturn.rbegin(); it != toReturn.rend(); ++it)
			{
				eventQueue.push(*it);
			}
		};

	auto post_json = [&](const std::string& body, bool batched) -> bool
		{
			HttpRequest request;
			request.url = ServerEndpoint;
			request.cookie = "";
			request.body = body;
			request.requestHeaders = {
				"Content-Type: application/json",
				"Accept: application/json",
				"User-Agent: MonitorLibTelemetry/1.0",
				batched ? "X-Batch: 1" : "X-Batch: 0"
			};

			if (!HttpClient::PostRequest(request))
			{
				return false;
			}

			//success if any header line contains '200 OK'
			bool ok = std::any_of(
				request.responseHeaders.begin(), request.responseHeaders.end(),
				[](const std::string& h) { return h.find("200 OK") != std::string::npos; }
			);
			return ok;
		};

	//try batched send first
	nlohmann::json arr = nlohmann::json::array();
	//arr.reserve(batch.size());

	for (const auto& ev : batch)
		arr.push_back(nlohmann::json(ev));

	const std::string batchBody = arr.dump(); // compact

	int attempt = 0;
	while (attempt < MAX_RETRIES)
	{
		if (post_json(batchBody, /*batched=*/true))
		{
#ifdef _LOGGING_ENABLED
			printf("Batch (%zu events) sent successfully\n", batch.size());
#endif
			return true;
		}
		++attempt;
#ifdef _LOGGING_ENABLED
		printf("Batch send failed (attempt %d/%d)\n", attempt, MAX_RETRIES);
#endif
		// exponential backoff
		std::this_thread::sleep_for(std::chrono::milliseconds(BASE_BACKOFF_MS * attempt));
	}

#ifdef _LOGGING_ENABLED
	printf("Batch send failed after retries. Falling back to single-event sends.\n");
#endif

	// 3) Fallback: send each event individually; if any fails, requeue remainder and stop
	for (size_t i = 0; i < batch.size(); ++i)
	{
		const auto& ev = batch[i];
		nlohmann::json j = ev;
		const std::string body = j.dump();

		bool sent = false;
		attempt = 0;
		while (attempt < MAX_RETRIES)
		{
			if (post_json(body, /*batched=*/false))
			{
				sent = true;
				break;
			}
			++attempt;
#ifdef _LOGGING_ENABLED
			printf("Single send failed (attempt %d/%d)\n", attempt, MAX_RETRIES);
#endif
			std::this_thread::sleep_for(std::chrono::milliseconds(BASE_BACKOFF_MS * attempt));
		}

		if (!sent)
		{
#ifdef _LOGGING_ENABLED
			printf("Single-event send failed after retries; re-queuing remaining %zu events\n",
				(batch.size() - i));
#endif
			// Requeue current & remaining events to preserve order
			std::vector<TelemetryEvent> remaining(batch.begin() + i, batch.end());
			requeue_preserve_order(remaining);
			return false;
		}
	}

#ifdef _LOGGING_ENABLED
	printf("All %zu events sent individually after batch failure\n", batch.size());
#endif
	return true;
}

/**
 * @brief Returns the current unix timestamp in milliseconds
 * @return 64-bit unsigned integer representing the unix timestamp in milliseconds
 * @usage  uint64_t timestampMS = EventLogger::GetUnixTimestampMs();
 */
uint64_t Telemetry::GetUnixTimestampMs()
{
	using namespace std::chrono;
	return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

/**
 * @brief Sets the data endpoint location
 * @details  Should be a URL supporting HTTP(s) requests
 * @return void
 */
void Telemetry::SetEndpoint(const std::string& endpoint)
{
	if (endpoint.empty())
	{
#ifdef _LOGGING_ENABLED
		printf("Endpoint was empty @ SetEndpoint\n");
#endif
	}

	this->ServerEndpoint = endpoint;
}

/**
 * @brief Generates a pseudo-unique client ID based on the computer's MachineGuid and computer name
 * @return std::string containing the generated client ID
 */
std::string Telemetry::GenerateClientId()
{
	wchar_t buf[256]{ 0 };
	DWORD cb = sizeof(buf);
	LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Cryptography",
		L"MachineGuid",
		RRF_RT_REG_SZ, nullptr, buf, &cb);

	//Get computer name
	char computerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(computerName) / sizeof(computerName[0]);

	if (!GetComputerNameA(computerName, &size))
	{
		strcpy_s(computerName, "UNKNOWN");
	}

	std::string result = std::string(computerName) + std::string("-") + StrHelper::WStringToString(buf);
	return result;
}