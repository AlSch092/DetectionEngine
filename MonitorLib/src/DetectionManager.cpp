//By AlSch092 @ Github
#include "../include/DetectionManager.hpp"
#include "../include/DetectionIncludes.hpp"
#include "../include/json/json.hpp"
#include "../include/ntldr.hpp"
#include "../../HttpLib/HttpLib.hpp"
#include "../include/StrHelper.hpp"
#include "../include/Obfuscation/CryptMgrTwoFish.h"
#include "../include/EventLog.hpp"

#include <future>
#include <thread>
#include <queue>
#include <mutex>

using json = nlohmann::json;

void to_json(json& j, const DetectionRule& dr);
inline void from_json(const nlohmann::json& j, DetectionRule& rule);

/**
 * @brief the Impl structure is used to hide implementation details of the DetectionManager class, using the PIMPL idiom
 */
struct DetectionManager::Impl
{
	DetectionManager* Manager = nullptr;

	uint32_t OurPID = GetCurrentProcessId();

	//Settings
	bool bMonitorProcessCreation = false;
	bool bGetDllNotifications = false;
	bool bCheckUnsignedModules = false;

	std::atomic<bool> bIsProcessCreationHooked = false;
	std::atomic<bool> bIsProcessCloseHooked = false;
	bool bIsWMIOperational = false;

	std::wstring CurrentProcessPath = ProcessHelper::GetProcessPathByPID(GetCurrentProcessId()); //save a bit of compute for future flagging

	std::vector<std::wstring> LoadedModules;
	std::mutex LoadedModulesMutex;

	static VOID CALLBACK OnDllNotification(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);
	PVOID DllNotificationRegistrationCookie = nullptr;

	std::condition_variable DLLQueueCV; //wake variable
	std::queue<std::wstring> DLLVerificationQueue;
	std::mutex DLLVerificationQueueMutex;
	
	std::unordered_set<std::wstring> PassedCertCheckModules;
	std::unordered_set<std::wstring> UnsignedLoadedModules;

	std::list<PROCESS_DATA> SuspiciousProcesses;

	std::unique_ptr<WMI> WMIManager = nullptr;

	std::atomic<bool> bStopRequested = false; //stop sig checking new modules

	std::atomic<uint32_t> MonitoredProcessId = 0; //such as a specific game pid, incase the lib is used to protect an another running process

	/**
	 * @brief  Schedules the Detection Engine for shutdown
	 * @return None
	 */
	void Shutdown()
	{
#ifdef _LOGGING_ENABLED
		OutputDebugStringA("IMPL::Shutdown() called!\n");
#endif
		this->bStopRequested = true;
		this->Manager->ScheduleShutdown(true);
	}

	/**
	 * @brief Impl struct constructor
	 * @param
	 * @return
	 */
	Impl(DetectionManager* DM)
	{
		if (DM == nullptr)
		{
			throw std::runtime_error("Null pointer error");
		}

		this->bStopRequested.store(false);

		try
		{
			this->WMIManager = std::make_unique<WMI>();
		}
		catch (const std::bad_alloc& ex)
		{
			throw std::runtime_error("[ERROR] Failed to create WMI object ptr!");
		}

#ifdef _LOGGING_ENABLED
		OutputDebugStringA("DetectionEngine starting up...\n");
#endif
	}

	/**
	 * @brief  Impl struct destructor
	 * @return None
	 */
	~Impl()
	{
#ifdef _LOGGING_ENABLED
		OutputDebugStringA("~IMPL called\n");
#endif
		Manager->ScheduleShutdown(true);

		bStopRequested.store(true);

		DLLQueueCV.notify_all(); //awaken waiting vars

		if (moduleSigCheckerThread.joinable())
			moduleSigCheckerThread.join();

		if (processCreationChecker.joinable())
			processCreationChecker.join();

		if (processTerminationChecker.joinable())
			processTerminationChecker.join();
		
		{   //remove dll callbacks
			HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

			if (hNtdll == 0)
				hNtdll = LoadLibraryA("ntdll.dll");

			typedef NTSTATUS(NTAPI* pfnLdrUnregisterDllNotification)(PVOID Cookie);

			pfnLdrUnregisterDllNotification pLdrRegisterDllNotification = (pfnLdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

			pLdrRegisterDllNotification(DllNotificationRegistrationCookie);
			DllNotificationRegistrationCookie = nullptr;
		}
	}

	/**
	 * @brief Runs all scan types and returns a list of detected flags
	 * @param bRunNonProcessScans Whether or not to run non-process targeted scans
	 * @param bRunSysConfigScans Whether or not to run system config scans
	 * @return Vector of DetectionResult objects representing any flagged findings
	 */
	std::vector<DetectionResult> RunAll(__in const bool bRunNonProcessScans, __in const bool bRunSysConfigScans) //*these routines dont add results to the detected list*
	{
		std::vector<DetectionResult> results;

		if (bRunSysConfigScans)
		{
			std::vector<DetectionResult> sysCfgScanResults = RunSystemConfigScans();
			results.insert(results.end(), sysCfgScanResults.begin(), sysCfgScanResults.end());
		}
		    	
		if (bRunNonProcessScans)
		{
			std::vector<DetectionResult> nonProcScanResults = RunNonProcessScans();
			results.insert(results.end(), nonProcScanResults.begin(), nonProcScanResults.end());
		}
		    
		return results;
	}

	/**
	 * @brief Runs process targeted scans on a particular process id
	 * @param pid  The process ID to run scans on
	 * @return  Vector of DetectionResult objects representing any flagged findings
	 */
	std::vector<DetectionResult> RunProcessScans(uint32_t pid) //these scans target a specific PID, usd in process creation callback
	{
		std::vector<DetectionResult> results;
		std::vector<DWORD> processesToTerminate;
		std::vector<uint32_t> flagIdReason;

		std::vector<std::shared_ptr<IDetector>> snapshot;
		{
			std::lock_guard<std::mutex> lck(Manager->DetectorListMutex);
			snapshot.reserve(Manager->Detectors.size());
			for (auto& sp : Manager->Detectors)
			{
				if (sp->Enabled() && sp->IsProcessScan() && !sp->IsSelfScan())
					snapshot.push_back(sp);    // bumps refcount; safe after unlock
			}
		}

		for (auto& d : snapshot)
		{
			if (d->IsOneTimeCheck() && d->DidOneTimeCheck())
			{
				continue;
			}
			else if(!d->IsSystemConfigScan())
			{
				if (d->GetId() == ScanIds::ProcessHandles)
					d->SetTargetProcess(GetCurrentProcessId());

#ifdef _LOGGING_ENABLED
				OutputDebugStringW(L"Running process scan: \n");
				OutputDebugStringW(std::to_wstring(d->GetId()).c_str());
				OutputDebugStringW(L"\n");
#endif

				d->SetTargetProcess(pid);// will this work with ptr copies?
				auto result = d->Run();
				result.AssociatedScanIds.push_back(static_cast<ScanIds>(d->GetId()));
				results.push_back(result);

				if (result.Flag > DetectionFlags::EXECUTION_ERROR)
				{
					if (d->ShouldTerminateOffendingProcess())
					{
						processesToTerminate.push_back(pid);
						flagIdReason.push_back(result.Flag);
					}
				}
			}
		}

		int loopCounter = 0;

		for (const DWORD pid : processesToTerminate)
		{
			HandleGuard hProc = HandleGuard(OpenProcess(PROCESS_TERMINATE, FALSE, pid));

			if (hProc.isValid())
			{
				if (!TerminateProcess(hProc.get(), 0))
				{
					//create remote thread on ExitProcess?
				}
			}
			else
			{   //log telemetry about failure to terminate?
#ifdef _LOGGING_ENABLED
				OutputDebugStringA("FAILED TO TERMINATE PROCESS..\n");
#endif
			}
		
			if (Manager->UsingTelemetry()) //push telemetry event that we terminated process
			{ 
				if (loopCounter <= flagIdReason.size())
				{
					Manager->TelemetryManager->LogEvent(TelemetryEvent(
						Manager->GetTelemetryManager()->FetchAddEventId(),
						Manager->GetTelemetryManager()->GetClientId(),
						TelemetryEvent::Action::TerminatedProcess, 
						pid,
						StrHelper::WStringToString(ProcessHelper::GetProcessPathByPID(pid)), 
						flagIdReason[loopCounter++]
					));
				}
				else  //fallback if for some reason vector sizes are mismatched
				{
					Manager->TelemetryManager->LogEvent(TelemetryEvent(
						Manager->GetTelemetryManager()->FetchAddEventId(),
						Manager->GetTelemetryManager()->GetClientId(),
						TelemetryEvent::Action::TerminatedProcess, 
						pid,
						StrHelper::WStringToString(ProcessHelper::GetProcessPathByPID(pid)), 
						0
					));
				}
			}
		}

		return results;
	}

	/**
	 * @brief Runs non-process targeted scans
	 * @return  Vector of DetectionResult objects representing any flagged findings
	 */
	std::vector<DetectionResult> RunNonProcessScans()
	{
		std::vector<DetectionResult> results;

		std::vector<std::shared_ptr<IDetector>> snapshot;
		{
			std::lock_guard<std::mutex> lck(Manager->DetectorListMutex);
			snapshot.reserve(Manager->Detectors.size());
			for (auto& sp : Manager->Detectors)
			{
				if (sp->Enabled() && !sp->IsProcessScan() && !sp->IsSystemConfigScan())
					snapshot.push_back(sp);    // bumps refcount; safe after unlock
			}
		}

		for (auto& det : snapshot)
		{
			if (det->IsProcessScan() || det->IsSystemConfigScan())
				continue;

			if ((det->IsOneTimeCheck() && det->DidOneTimeCheck()))
			{
				continue;
			}

#ifdef _LOGGING_ENABLED
			OutputDebugStringA("Running scan: ");
			OutputDebugStringA(std::to_string(det->GetId()).c_str());
			OutputDebugStringA("\n");
#endif
			auto result = det->Run();

			results.push_back(result);
		}

		return results;
	}

	/**
	 * @brief  Runs all registered system configuration scans
	 * @return  Vector of DetectionResult objects representing any flagged findings
	 */
	std::vector<DetectionResult> RunSystemConfigScans()
	{
		std::vector<DetectionResult> results;

		std::vector<std::shared_ptr<IDetector>> snapshot;
		{
			std::lock_guard<std::mutex> lck(Manager->DetectorListMutex);
			snapshot.reserve(Manager->Detectors.size());
			for (auto& sp : Manager->Detectors)
			{
				if (sp->Enabled() && sp->IsSystemConfigScan() && !sp->IsProcessScan())
					snapshot.push_back(sp);    // bumps refcount; safe after unlock
			}
		}

		for (auto& d : snapshot)
		{
			if (d->IsOneTimeCheck() && d->DidOneTimeCheck())
			{
				continue;
			}
			else if (d->IsSystemConfigScan())
			{
				auto result = d->Run();
				result.AssociatedScanIds.push_back((uint32_t)d->GetId());
				results.push_back(result);
				
				if (d->ShouldShutdownOnFlag() && result.Flag > DetectionFlags::EXECUTION_ERROR)
				{
#ifdef _LOGGING_ENABLED
					OutputDebugStringW(L"ShutdownOnFlag triggered, ending program...");
					OutputDebugStringW(std::to_wstring(result.Flag).c_str());
#endif

					Manager->pImpl->Shutdown();

					if (Manager->UsingTelemetry())
					{
						TelemetryEvent te1(Manager->GetTelemetryManager()->FetchAddEventId(),
							Manager->GetTelemetryManager()->GetClientId(),
							TelemetryEvent::Action::Flag, OurPID,
							"", result.Flag);

						TelemetryEvent te2(Manager->GetTelemetryManager()->FetchAddEventId(),
							Manager->GetTelemetryManager()->GetClientId(),
							TelemetryEvent::Action::SelfShutdown, OurPID,
							"", result.Flag);

						Manager->TelemetryManager->LogEvent(te1, te2);
					}

					break;
				}
			}
		}

		return results;
	}

	void SetMonitoredProcessId(const uint32_t pid) noexcept     //If we want to protect a separate running process
	{
		this->MonitoredProcessId = pid;
	}

	static void DoNonProcessScan(__in DetectionManager* thisPtr);
	std::thread NonProcessChecksThread;

	static void MonitorProcessCreation(__in DetectionManager* thisPtr);
	std::thread processCreationChecker;

	static void MonitorProcessTermination(__in DetectionManager* Manager);
	std::thread processTerminationChecker;

	std::thread moduleSigCheckerThread;
	static void CheckDLLSignatures(DetectionManager* DM);

	std::mutex PassedCertCheckListMutex;
	std::mutex ModuleListMutex;
};

/**
 * @brief Constructs an DetectionManager object
 *
 * @return DetectionManager class object
 *
 * @usage
 * DetectionManager* detector = new DetectionManager();
 */
DetectionManager::DetectionManager(const bool bUsingTelemetry, const std::string& TelemetryEndpoint, const bool bMonitorProcessCreation, const bool bGetDllNotifications, const bool bCheckUnsignedModules) : pImpl(new DetectionManager::Impl(this))
{
	this->bScheduledShutdown.store(false);
	this->pImpl->Manager = this;
	this->pImpl->bMonitorProcessCreation = bMonitorProcessCreation;
	this->pImpl->bGetDllNotifications = bGetDllNotifications;
	this->pImpl->bCheckUnsignedModules = bCheckUnsignedModules;

	this->UseTelemetry(bUsingTelemetry); //will put this in constructor arg later

	if (this->UsingTelemetry())
	{
		try
		{
			this->TelemetryManager = std::make_unique<Telemetry>();
		}
		catch (const std::bad_alloc& ex)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Failed to allocate telemetry smart ptr!" << std::endl;
#endif
			this->UseTelemetry(false);
		}

		this->TelemetryManager->SetEndpoint(TelemetryEndpoint);
		this->TelemetryManager->Start();
	}

	
	if (!this->pImpl->WMIManager->IsWMIServiceRunning())
	{
		if (!this->pImpl->WMIManager->StartWMIService()) //log to event log
		{
			EventLog evl(L"Lighthouse");
			constexpr auto msg = XorStr::make_encrypted(L"Cannot start program: WMI Service could not be enabled");
			evl.error(msg.decrypt().c_str());
			std::terminate();
		}
	}
	
	if (this->pImpl->WMIManager->InitializeCOM())
	{
		ComPtr<IWbemServices> tmp;

		if (SUCCEEDED(this->pImpl->WMIManager->ConnectToWMI(tmp)))
		{
			this->pImpl->WMIManager->SetwmiInterface(tmp); // holds a ref safely
		}
	}
	else
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "InitializeCOM failed: " << GetLastError() << std::endl;
#endif
		throw std::runtime_error("COM Init failure");
	}

}

/**
 * @brief Called on destruction of a DetectionManager object
 * 
 * @details Cleans up resources used by the DetectionManager object
 * 
 * @return None
 */
DetectionManager::~DetectionManager()
{
	if (pImpl)
	{
		pImpl->bStopRequested.store(true);

		pImpl->DLLQueueCV.notify_all();

		if (pImpl->moduleSigCheckerThread.joinable())
			pImpl->moduleSigCheckerThread.join();

		if (pImpl->NonProcessChecksThread.joinable())
			pImpl->NonProcessChecksThread.join();

		if (pImpl->processCreationChecker.joinable())
			pImpl->processCreationChecker.join();

		if (pImpl->processTerminationChecker.joinable())
			pImpl->processTerminationChecker.join();

		if (pImpl->DllNotificationRegistrationCookie)
		{
			HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

			if (hNtdll)
			{
				auto LdrUnregisterDllNotification = (NTSTATUS(NTAPI*)(PVOID))GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

				if (LdrUnregisterDllNotification)
					LdrUnregisterDllNotification(pImpl->DllNotificationRegistrationCookie);
			}
		}
	}
}

std::list<PROCESS_DATA> DetectionManager::GetSuspiciousProcesses()
{
	std::lock_guard<std::mutex> lock(SuspiciousProcessMutex);
	return this->pImpl->SuspiciousProcesses;
}

void DetectionManager::AddSuspiciousProcess(__in const uint32_t pid, __in const std::wstring& path, __in const ScanIds flaggedByScan)
{
	if (pid <= 4)
		return;

	PROCESS_DATA p;
	p.pid = pid;
	p.path = path;
	p.FlaggedByScans.push_back(flaggedByScan);
	FillProcessInfo(p);

	std::lock_guard<std::mutex> lock(SuspiciousProcessMutex);

	auto it = std::find(this->pImpl->SuspiciousProcesses.begin(), this->pImpl->SuspiciousProcesses.end(), p);

	if (it == this->pImpl->SuspiciousProcesses.end()) //first time seeing process -> add to list
	{
		this->pImpl->SuspiciousProcesses.push_back(p);
	}
	else
	{
		if (std::find(it->FlaggedByScans.begin(), it->FlaggedByScans.end(), flaggedByScan) == it->FlaggedByScans.end())
			it->FlaggedByScans.push_back(flaggedByScan); //second time seeing process -> add flagged ID to proc already in list
	}
}

void DetectionManager::AddSuspiciousProcess(__in const PROCESS_DATA& pd)
{
	std::lock_guard<std::mutex> lock(SuspiciousProcessMutex);

	if (std::find(this->pImpl->SuspiciousProcesses.begin(), this->pImpl->SuspiciousProcesses.end(), pd) == this->pImpl->SuspiciousProcesses.end())
	{
		this->pImpl->SuspiciousProcesses.push_back(pd);
	}
}

void DetectionManager::FillProcessInfo(__in PROCESS_DATA& p)
{
	HandleGuard hProc = HandleGuard(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));

	p.bCanObtainHandle = hProc.isValid();

	auto sigFuture = std::async(std::launch::async, [&p]()
		{
			return Authenticode::HasSignature(p.path.c_str(), TRUE);
		});


	p.bIsWoW64 = ProcessHelper::IsProcessWoW64(hProc.get());

	if (p.path.empty())
	{
		p.path = ProcessHelper::GetProcessImagePath(hProc.get());
		p.baseName = ProcessHelper::GetProcessName(p.pid);
	}
	else
		p.baseName = p.path.substr(p.path.find_last_of('\\') + 1, p.path.length() - p.path.find_last_of('\\') - 1);

	_CRC32 crc;
	p.fileHash = crc.calculate(StrHelper::WStringToString(p.path));

	if (hProc.isValid())
	{
		//get file size
	}

	p.bIsSigned = sigFuture.get();
}

/**
 * @brief Parses a `DetectionRule` structure into an actual scan and adds it to `Detectors`
 * 
 * @param `rule`  Detection rule to add to the Detectors scan list
 * 
 * @return None
 * 
 * @usage  DetectionRule rule;  DM->RegisterRule(rule);
 */
void DetectionManager::RegisterRule(__in const DetectionRule& rule)
{
	switch (rule.id)
	{
		case ScanIds::ByteSignature:
		{
			auto scan = std::make_shared<ByteSignatureScan>(rule); //leave the `scan` var declared incase we need to use it for something else later on
		
			if (this->pImpl->MonitoredProcessId != 0)
			{
				scan->SetTargetProcess(this->pImpl->MonitoredProcessId);
				scan->SetFixedProcessId(true);
			}

			Register(std::move(scan));
			break;
		}
		case ScanIds::ProcessHandles:
		{
			auto scan = std::make_shared<ProcessHandlesScan>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::FileHash:
		{
			auto scan = std::make_shared<FileHashScanner>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::ManualMap:
		{
			auto scan = std::make_shared<ManualMappedModuleScan>(rule);

			if (this->pImpl->MonitoredProcessId != 0)
			{
				scan->SetTargetProcess(this->pImpl->MonitoredProcessId);
				scan->SetFixedProcessId(true);
			}

			Register(std::move(scan));
			break;
		}
		case ScanIds::ProcessString:
		{
			auto scan = std::make_shared<ProcessStringScanner>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::HVCI:
		{
			auto scan = std::make_shared<HVCIScan>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::SecureBoot:
		{
			auto scan = std::make_shared<SecureBootScan>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::DriverSignatureEnforcement:
		{
			auto scan = std::make_shared<DriverSignatureEnforcementScan>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::Hypervisor:
		{
			auto scan = std::make_shared<HypervisorScan>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::ProcessIsAdmin:
		{
			auto scan = std::make_shared<ProcessElevatedScan>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::IATModified:
		{
			auto scan = std::make_shared<IATScan>(rule);
		
			if (this->pImpl->MonitoredProcessId != 0)
			{
				scan->SetTargetProcess(this->pImpl->MonitoredProcessId);
				scan->SetFixedProcessId(true);
			}
		
			Register(std::move(scan));
			break;
		}
		case ScanIds::UnsignedLoadedModule:
		{
			auto scan = std::make_shared<UnsignedLoadedModulesScan>(rule);
			Register(std::move(scan));
			break;
		}
		case ScanIds::ProcessCommandLine:
		{
			auto scan = std::make_shared<CommandLineScan>(rule);
			Register(std::move(scan));
			break;
		}

		case ScanIds::ResourceUsage:
		{
			auto scan = std::make_shared<ResourceUsageScan>(rule);
			Register(std::move(scan));
			break;
		}

		case ScanIds::NetworkConnection:
		{
			auto scan = std::make_shared<NetworkScan>(rule);
			Register(std::move(scan));
			break;
		}

		case ScanIds::LoadedDrivers:
		{
			auto scan = std::make_shared<LoadedDriverScan>(rule);
			Register(std::move(scan));
			break;
		}

		case ScanIds::ProcessEnumerator:
		{
			auto scan = std::make_shared<ProcessScan>(rule);
			Register(std::move(scan));
			break;
		}

		default:
		{
	#ifdef _LOGGING_ENABLED
			std::cerr << "Unknown scan ID in registration: " << rule.id << std::endl;
	#endif
			break;
		}

	}
}

bool DetectionManager::FetchDetectionRules(__in const std::string& location, __in const bool bShouldDecrypt)
{
	if (location.empty())
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "url was empty @ FetchDetectionRules" << std::endl;
#endif
		return false;
	}

	this->AddDetectionsRepository(location);

	std::string jsonText;

	if (location.find("http://") != std::string::npos || location.find("https://") != std::string::npos)
	{
		HttpRequest request;
		request.cookie = ""; //no cookie for now, may add later
		request.url = location;
		request.body = "";
		request.requestHeaders.push_back("User-Agent: MonitorEngine (Win64; x64)");
		request.requestHeaders.push_back("Accept: application/json");

		if (!HttpClient::GetRequest(request))
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "GET Request failed @ FetchDetectionRules" << std::endl;
#endif
			return false;
		}

		jsonText = request.responseText;
	}
	else if (location.find(".json"))
	{
		std::string fileText;
		std::string line;

		std::ifstream ifs(location);

		while (getline(ifs, line))
			jsonText += line;

		ifs.close();
	}
	
	if (bShouldDecrypt)
	{	
		char* buf_cpy = new char[jsonText.length() + 16] {0}; //block cipher pads to nearest 16 bytes, add extra buffer space or risk overflow
		memcpy(buf_cpy, jsonText.data(), jsonText.length()); //don't use strcpy_s, will fail if any 0x00 is found in the encrypted file early on

		std::string decrypted = CCryptMgrTwoFish::Decrypt(buf_cpy, static_cast<const long>(jsonText.length()));

		if (buf_cpy)
			delete[] buf_cpy;

		if (!decrypted.empty())
			jsonText = decrypted;
		else
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Decryption failed @ FetchDetectionRules\n";
#endif
			return false;
		}
	}

	std::vector<DetectionRule> rules;

	try
	{
		nlohmann::json j = nlohmann::json::parse(jsonText);
		j.get_to(rules);
	}
	catch (...)
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Parsing detection rule from response failed @ FetchDetectionRules" << std::endl;
		OutputDebugStringW(L"Parsing detection rule from response failed @ FetchDetectionRules \n");
#endif

		return false;
	}

	if (rules.empty())
	{
#ifdef _LOGGING_ENABLED
		OutputDebugStringW(L"Rules list was empty @ FetchDetectionRules\n");
		std::cerr << "Rules list was empty @ FetchDetectionRules" << std::endl;
#endif
		return false;
	}

	for (const auto& rule : rules)
	{
		RegisterRule(rule);
	}


#ifdef _LOGGING_ENABLED
	OutputDebugStringW(L"Detectors size: \n");
	OutputDebugStringW(std::to_wstring(Detectors.size()).c_str());
#endif

	return true;
}

/**
 * @brief Sets up WMI for process callbacks and runs inital detections
 *
 * @return true/false if setup succeeded or not
 *
 */
bool DetectionManager::StartDetections()
{
	if (this->pImpl->WMIManager->GetWMIInterface() == nullptr)
	{
#ifdef _LOGGING_ENABLED
		OutputDebugStringA("wmiInterface Ptr was NULL @ StartDetections\n");
#endif
		return false;
	}

	pImpl->bIsWMIOperational = true;

	if (this->pImpl->bGetDllNotifications)
	{
		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

		if (hNtdll != 0) //register DLL notifications callback 
		{
			_LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
			NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)DetectionManager::Impl::OnDllNotification, this, &this->pImpl->DllNotificationRegistrationCookie);
		}
	}

	if (this->pImpl->bCheckUnsignedModules)
		this->pImpl->moduleSigCheckerThread = std::thread(DetectionManager::Impl::CheckDLLSignatures, this);

	if (this->pImpl->bMonitorProcessCreation)
		this->pImpl->processCreationChecker = std::thread(DetectionManager::Impl::MonitorProcessCreation, this);

	if (this->pImpl->bMonitorProcessCreation)
		this->pImpl->processTerminationChecker = std::thread(DetectionManager::Impl::MonitorProcessTermination, this);

	this->pImpl->NonProcessChecksThread = std::thread(DetectionManager::Impl::DoNonProcessScan, this);

	//we need to do one set of initial process scans on all processes to catch any processes opened before this process was opened
	std::thread initialProcessScanThread([this]()
		{
			std::vector<PROCESS_DATA> procs = ProcessScan::GetProcesses();

			if (procs.empty()) //error!
			{
				EventLog log(L"Lighthouse");
				log.error(L"Could not enumerate processes at startup");
				throw std::runtime_error("[ERROR] Could not enumerate processes at startup");
			}

			std::vector<DetectionResult> resultsList;

			for (const auto& proc : procs)
			{
				auto results = this->pImpl->RunProcessScans(proc.pid);

				for (const auto& result : results)
				{
					if (result.Flag > DetectionFlags::EXECUTION_ERROR)
					{
						this->AddDetected(result);
						this->AddSuspiciousProcess(proc);
						resultsList.push_back(result);
					}
				}

			}

			for (const auto& result : resultsList)
			{
				uint32_t s = result.AssociatedScanIds.front();

				if (s == 0)
				{
					EventLog log(L"Lighthouse");
					log.error(L"Error fetching scan ID associated with flagged process");
					continue;
				}

				std::shared_ptr<IDetector> det = this->GetDetectorWithId(static_cast<ScanIds>(s));

				if (det && det->ShouldTerminateOffendingProcess())
				{
					HandleGuard hProc(OpenProcess(PROCESS_TERMINATE, FALSE, result.ProcessId));

					if(hProc)
					{
						if (!TerminateProcess(hProc.get(), 0))
						{
							EventLog log(L"Lighthouse");
							std::wstring msg = L"Failed to terminate process: " + std::to_wstring(result.ProcessId);
							log.error(msg);

							//also tell telemetry?
						}
					}
				}
			}


		});

	initialProcessScanThread.detach();

	return true;
}

/**
 * @brief Runs non-process targeted scans periodically (such as open process handle checks)
 * @param `Manager`  Pointer to DetectionManager object
 * @return true/false if setup succeeded or not
 */
void DetectionManager::Impl::DoNonProcessScan(__in DetectionManager* Manager)
{
	if (!Manager)
		return;

	while (!Manager->pImpl->bIsProcessCreationHooked)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	}

	while (Manager->Detectors.empty())
	{
#ifdef _LOGGING_ENABLED
		std::cout << "Waiting for detection list...\n";
#endif
		std::this_thread::sleep_for(std::chrono::milliseconds(3000));
	}

#ifdef _LOGGING_ENABLED
	OutputDebugStringA("Running system check scans...\n");
#endif

	auto systemConfigScanResults = Manager->pImpl->RunSystemConfigScans(); //should only need to do sysconfig scans once

	for (const auto& result : systemConfigScanResults)
	{
		if(result.Flag > DetectionFlags::EXECUTION_ERROR)
		    Manager->AddDetected(result);
	}

#ifdef _LOGGING_ENABLED
	OutputDebugStringA("Starting non-process scans..\n");
#endif

	std::thread runContinuousScans([](DetectionManager* DM)   //run continuous scans (recommended, resource usage scan)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10000));

			std::vector<std::shared_ptr<IDetector>> snapshot;
			{
				std::lock_guard<std::mutex> lck(DM->DetectorListMutex);
				snapshot.reserve(DM->Detectors.size());
				for (auto& sp : DM->Detectors) 
				{
					if (sp->IsContinuousScan())
						snapshot.push_back(sp);
				}
			}

			if (snapshot.empty())
				return;

			while (!DM->pImpl->bStopRequested.load())
			{
				for (auto& d : snapshot)
				{
					try
					{
						auto result = d->Run();

						if (result.Flag > DetectionFlags::EXECUTION_ERROR)
						{
#ifdef _LOGGING_ENABLED
							OutputDebugStringW(L"[+] Detector (non-process, continuous) alerted with flag: ");
							OutputDebugStringW(std::to_wstring(static_cast<ScanIds>(result.Flag)).c_str());
							OutputDebugStringW(L"\n");
#endif
							
							DM->AddDetected(result);
							//DM->PrintDetectedFragments();

							if (DM->UsingTelemetry())
							{
								DM->TelemetryManager->LogEvent(TelemetryEvent(
									DM->GetTelemetryManager()->FetchAddEventId(),
									DM->GetTelemetryManager()->GetClientId(),
									TelemetryEvent::Action::Flag, 
									result.ProcessId,
									StrHelper::WStringToString(ProcessHelper::GetProcessPathByPID(result.ProcessId)), 
									result.Flag));
							}
						}
					}
					catch (...)
					{

				    }
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(1000)); //still wait a small bit for continuous scans to avoid overload
			}
		}, Manager);
	runContinuousScans.detach();

	while (!Manager->pImpl->bStopRequested.load())
	{
		if (!Manager->pImpl->bIsProcessCreationHooked || !Manager->pImpl->bIsWMIOperational) //shutdown if WMI or process creation is not running 
		{
			OutputDebugStringA("bIsProcessCreationHooked FAIL or bIsWMIOperational FAIL");
			if (!Manager->bScheduledShutdown.load())
				Manager->pImpl->Shutdown();

			//todo: add check if COM/WMi service is unloaded?

			throw std::runtime_error("WMI failure");
		}

		auto scanResults = Manager->pImpl->RunNonProcessScans();

		for (const auto& result : scanResults)
		{
			if (result.Flag > DetectionFlags::EXECUTION_ERROR)
			{
#ifdef _LOGGING_ENABLED
				OutputDebugStringW(L"[+] Detector (non-process) alerted with flag: ");
				OutputDebugStringW(std::to_wstring(static_cast<ScanIds>(result.Flag)).c_str());
				OutputDebugStringW(L"\n");
#endif

				Manager->AddDetected(result);
				//Manager->PrintDetectedFragments();

				if (Manager->UsingTelemetry())
				{
					Manager->TelemetryManager->LogEvent(TelemetryEvent(
						Manager->GetTelemetryManager()->FetchAddEventId(),
						Manager->GetTelemetryManager()->GetClientId(),
						TelemetryEvent::Action::Flag,
						result.ProcessId,
						StrHelper::WStringToString(ProcessHelper::GetProcessPathByPID(result.ProcessId)),
						result.Flag));
				}

			}
			else if (result.Flag == DetectionFlags::EXECUTION_ERROR)
			{
			}
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(10000));
	}
}

/**
 * @brief  Uses WMI to monitor process creation events
 * @param  `Manager` DetectionManager object
 * @return None
 */
void DetectionManager::Impl::MonitorProcessCreation(__in DetectionManager* Manager)
{
	if (!Manager) 
		return;

	HRESULT hres;

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);

	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Failed to initialize COM library @ MonitorNewProcesses\n");
#endif
		return;
	}

	IWbemLocator* pLoc = nullptr;

	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Failed to create IWbemLocator object @ MonitorProcessCreation\n");
#endif
		CoUninitialize();
		return;
	}

	IWbemServices* pSvc = nullptr;

	constexpr auto encStr = XorStr::make_encrypted(L"ROOT\\CIMV2");

	hres = pLoc->ConnectServer(_bstr_t(encStr.decrypt().c_str()), NULL, NULL, 0, NULL, 0, 0, &pSvc);

	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Could not connect to WMI namespace @ MonitorProcessCreation\n");
#endif
		pLoc->Release();
		CoUninitialize();
		return;
	}

	hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Could not set proxy blanket @ MonitorProcessCreation\n");
#endif
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	constexpr auto wql = XorStr::make_encrypted(L"WQL");
	constexpr auto query = XorStr::make_encrypted(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

	IEnumWbemClassObject* pEnumerator = nullptr; //process create events

	hres = pSvc->ExecNotificationQuery((wchar_t*)wql.decrypt().c_str(), (wchar_t*)query.decrypt().c_str(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hres))
	{
#if USE_LOG_MESSAGES
		Logger::logf(Err, "Query registration for process creation events failed @ MonitorProcessCreation");
		OutputDebugStringA("Query registration for process creation events failed @ MonitorProcessCreation\n");
#endif
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	IWbemClassObject* pclsObj = nullptr;
	ULONG uReturn = 0;

	Manager->pImpl->bIsProcessCreationHooked = true;

	while (pEnumerator) //keep looping while MonitoringProcessCreation is set to true
	{
		if (Manager->IsShutdownScheduled())
		{
#ifdef _LOGGING_ENABLED
			OutputDebugStringA("Shutting down WMI process events..\n"); 
#endif
			break;
		}

		HRESULT hr = pEnumerator->Next(WBEM_NO_WAIT, 1, &pclsObj, &uReturn);

		if (0 == uReturn)
		{
			this_thread::sleep_for(std::chrono::milliseconds(100)); //ease the CPU a bit
			continue;
		}

		constexpr auto targetInstEnc = XorStr::make_encrypted(L"TargetInstance");
		constexpr auto nameEnc = XorStr::make_encrypted(L"Name");
		constexpr auto processIdEnc = XorStr::make_encrypted(L"ProcessId");

		VARIANT vtProp;
		VariantInit(&vtProp);

		hr = pclsObj->Get(targetInstEnc.decrypt().c_str(), 0, &vtProp, 0, 0);

		if (SUCCEEDED(hr) && (vtProp.vt == VT_UNKNOWN))
		{
			IUnknown* str = vtProp.punkVal;
			IWbemClassObject* pClassObj = nullptr;
			str->QueryInterface(IID_IWbemClassObject, (void**)&pClassObj);

			if (pClassObj)
			{
				VARIANT vtName; VariantInit(&vtName);
				VARIANT vtPid;  VariantInit(&vtPid);
				pClassObj->Get(nameEnc.decrypt().c_str(), 0, &vtName, nullptr, nullptr);
				pClassObj->Get(processIdEnc.decrypt().c_str(), 0, &vtPid, nullptr, nullptr);

				const uint32_t pid = (vtPid.vt == VT_UI4) ? (uint32_t)vtPid.ulVal : (vtPid.vt == VT_I4) ? (uint32_t)vtPid.lVal : 0U;
				
				std::wstring name = (vtName.vt == VT_BSTR && vtName.bstrVal) ? vtName.bstrVal : L"";

				auto pSvc = Manager->pImpl->WMIManager.get()->GetWMIInterface();

#ifdef _LOGGING_ENABLED
				if(!name.empty())
				    OutputDebugStringW(name.c_str());
#endif

				std::thread([Manager, pid, name]()
					{
					    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
#ifdef _LOGGING_ENABLED
					    OutputDebugStringW(L"Running process scans");
#endif
						auto results = Manager->pImpl->RunProcessScans(pid);
					
						for (const auto& r : results) 
						{
							if (r.Flag > DetectionFlags::EXECUTION_ERROR && r.ProcessId == pid) 
							{
								std::wstring path = ProcessHelper::GetProcessPathByPID(pid);

								if (Manager->UsingTelemetry())
								{
									Manager->TelemetryManager->LogEvent(TelemetryEvent(
										Manager->GetTelemetryManager()->FetchAddEventId(),
										Manager->GetTelemetryManager()->GetClientId(),
										TelemetryEvent::Action::Flag, 
										pid,
										StrHelper::WStringToString(path), 
										r.Flag));
								}

								Manager->AddDetected(r);
								Manager->AddSuspiciousProcess(pid, path, static_cast<ScanIds>(r.AssociatedScanIds.front()));  //check this for memory usage
							}
						}
					}).detach();

				if (Manager->UsingTelemetry())
				{
					 Manager->TelemetryManager->LogEvent(TelemetryEvent(
						 Manager->GetTelemetryManager()->FetchAddEventId(),
						 Manager->GetTelemetryManager()->GetClientId(),
						 TelemetryEvent::Action::ProcessOpen,
						 pid,
						 StrHelper::WStringToString(ProcessHelper::GetProcessPathByPID(pid)),
						 0));
				}

				VariantClear(&vtPid);
				VariantClear(&vtName);
				pClassObj->Release();
			}
		}

		VariantClear(&vtProp);
		this_thread::sleep_for(std::chrono::milliseconds(100)); //ease the CPU a bit
	}

	// Let ComPtr clean up; do NOT manual Release() on ComPtr-managed objects
	Manager->pImpl->bIsProcessCreationHooked = false;
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
}


/**
 * @brief  Uses WMI to monitor process termination events
 * @param  `Manager` DetectionManager object
 * @return None
 */
void DetectionManager::Impl::MonitorProcessTermination(__in DetectionManager* Manager)
{
	if (!Manager)
		return;

	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Failed to initialize COM library @ MonitorProcessTermination\n");
#endif
		return;
	}

	IWbemLocator* pLoc = nullptr;
	hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Failed to create IWbemLocator object @ MonitorProcessTermination\n");
#endif
		CoUninitialize();
		return;
	}

	constexpr auto encStr = XorStr::make_encrypted(L"ROOT\\CIMV2");

	IWbemServices* pSvc = nullptr;
	hres = pLoc->ConnectServer(_bstr_t(encStr.decrypt().c_str()), NULL, NULL, 0, NULL, 0, 0, &pSvc);

	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Could not connect to WMI namespace @ MonitorProcessTermination\n");
#endif
		pLoc->Release();
		CoUninitialize();
		return;
	}

	hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

	if (FAILED(hres))
	{
#if _LOGGING_ENABLED
		OutputDebugStringA("Could not set proxy blanket @ MonitorProcessTermination\n");
#endif
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	constexpr auto wql = XorStr::make_encrypted(L"WQL");
	constexpr auto query_del = XorStr::make_encrypted(L"SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

	IEnumWbemClassObject* pEnumerator = nullptr; //process create events

	hres = pSvc->ExecNotificationQuery((wchar_t*)wql.decrypt().c_str(), (wchar_t*)query_del.decrypt().c_str(), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hres))
	{
#if USE_LOG_MESSAGES
		Logger::logf(Err, "Query registration for process creation events failed @ MonitorProcessTermination");
		OutputDebugStringA("Query registration for process creation events failed @ MonitorProcessTermination\n");
#endif
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	IWbemClassObject* pclsObj = nullptr;
	ULONG uReturn = 0;

	Manager->pImpl->bIsProcessCloseHooked.store(true, std::memory_order_relaxed);

	while (pEnumerator)
	{
		if (Manager->IsShutdownScheduled())
		{
#ifdef _LOGGING_ENABLED
			OutputDebugStringA("Shutting down WMI process termination events..\n");
#endif
			break;
		}

		HRESULT hr = pEnumerator->Next(WBEM_NO_WAIT, 1, &pclsObj, &uReturn);

		if (0 == uReturn)
		{
			this_thread::sleep_for(std::chrono::milliseconds(100)); //ease the CPU a bit
			continue;
		}

		VARIANT vtProp;
		VariantInit(&vtProp);

		constexpr auto targetInstEnc = XorStr::make_encrypted(L"TargetInstance");
		constexpr auto nameEnc = XorStr::make_encrypted(L"Name");
		constexpr auto processIdEnc = XorStr::make_encrypted(L"ProcessId");

		hr = pclsObj->Get(targetInstEnc.decrypt().c_str(), 0, &vtProp, 0, 0);

		if (SUCCEEDED(hr) && (vtProp.vt == VT_UNKNOWN))
		{
			IUnknown* str = vtProp.punkVal;
			IWbemClassObject* pClassObj = nullptr;
			str->QueryInterface(IID_IWbemClassObject, (void**)&pClassObj);

			if (pClassObj)
			{
				VARIANT vtName; VariantInit(&vtName);
				VARIANT vtPid;  VariantInit(&vtPid);
				pClassObj->Get(nameEnc.decrypt().c_str(), 0, &vtName, nullptr, nullptr);
				pClassObj->Get(processIdEnc.decrypt().c_str(), 0, &vtPid, nullptr, nullptr);

				const uint32_t pid = (vtPid.vt == VT_UI4) ? (uint32_t)vtPid.ulVal : (vtPid.vt == VT_I4) ? (uint32_t)vtPid.lVal : 0U;

				std::wstring name = (vtName.vt == VT_BSTR && vtName.bstrVal) ? vtName.bstrVal : L"";

				auto pSvc = Manager->pImpl->WMIManager.get()->GetWMIInterface();

#ifdef _LOGGING_ENABLED
				OutputDebugStringW(L"PROCESS WAS CLOSED/TERMINATED:\n");
				if (!name.empty())
					OutputDebugStringW(name.c_str());
#endif				

				if (Manager->UsingTelemetry())
				{
					Manager->TelemetryManager->LogEvent(TelemetryEvent(
						Manager->GetTelemetryManager()->FetchAddEventId(),
						Manager->GetTelemetryManager()->GetClientId(),
						TelemetryEvent::Action::ProcessClose,
						pid,
						"", //can't fetch since process is closed already?
						0));
				}

				VariantClear(&vtPid);
				VariantClear(&vtName);
				pClassObj->Release();
			}
		}

		VariantClear(&vtProp);
		this_thread::sleep_for(std::chrono::milliseconds(100)); //ease the CPU a bit
	}

	// Let ComPtr clean up; do NOT manual Release() on ComPtr-managed objects
	Manager->pImpl->bIsProcessCloseHooked.store(false, std::memory_order_relaxed);
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
}

/**
 * @brief  DLL load/unload callback routine
 * @param `NotificationReason` Whether the dll was loaded or unloaded 
 * @param `NotificationData`  Contains information related to the loaded/unloaded module
 * @param `Context`  User-supplied pointer, in this case to the DetectionManager
 * @return None
 */
VOID CALLBACK DetectionManager::Impl::OnDllNotification(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
	DetectionManager* Manager = reinterpret_cast<DetectionManager*>(Context);

	if (Manager == nullptr)
	{
#ifdef _LOGGING_ENABLED
		wprintf(L"Manager was nullptr @ OnDllNotification!\n");
#endif
		return;
	}

	if (!NotificationData || !NotificationData->Loaded.FullDllName || !NotificationData->Loaded.FullDllName->pBuffer)
	{
#ifdef _LOGGING_ENABLED
		wprintf(L"FullDllName was nullptr @ OnDllNotification!\n");
#endif
		return;
	}

	const std::wstring FullDllName = NotificationData->Loaded.FullDllName->pBuffer;

	if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
	{
		//temp workaround for spam by this dll 
		if (StrHelper::ContainsStrW(L"\\windows\\system32\\secur32.dll", FullDllName) || StrHelper::ContainsStrW(L"\\windows\\system32\\sspicli.dll", FullDllName))
			return;

#ifdef _LOGGING_ENABLED
		wprintf(L"[LdrpDllNotification Callback] dll loaded: %s\n", FullDllName.c_str());
#endif
		{
			{
				std::lock_guard<std::mutex> lock(Manager->pImpl->DLLVerificationQueueMutex);
				Manager->pImpl->DLLVerificationQueue.push(FullDllName);
			}

			{
				std::lock_guard<std::mutex> lock(Manager->pImpl->LoadedModulesMutex);
				Manager->pImpl->LoadedModules.push_back(FullDllName);
			}
		}

		Manager->pImpl->DLLQueueCV.notify_one();
		
		std::shared_ptr<IDetector> base = Manager->GetDetectorWithId(ScanIds::FileHash);

		if (base != nullptr)
		{
			if (auto fhs = std::dynamic_pointer_cast<FileHashScanner>(base)) //also check file hashes of loaded modules
			{
				std::thread([Manager, fhs, FullDllName]
					{
						DetectionResult result = fhs->Run(FullDllName); 
						if (result.Flag > DetectionFlags::EXECUTION_ERROR)
						{
							Manager->AddDetected(result);
							//Add suspicious module to program list?

							if (Manager->UsingTelemetry())
							{
								Manager->TelemetryManager->LogEvent(TelemetryEvent(
									Manager->GetTelemetryManager()->FetchAddEventId(),
									Manager->GetTelemetryManager()->GetClientId(),
									TelemetryEvent::Action::Flag,
									GetCurrentProcessId(),
									StrHelper::WStringToString(Manager->pImpl->CurrentProcessPath),
									result.Flag));
							}

							printf("OnDllNotif caught file hash %s!\n", result.Description.c_str());
						}
					}).detach();
			}
		}

		if (Manager->UsingTelemetry() && Manager->TelemetryManager != nullptr)
		{
			Manager->TelemetryManager->LogEvent(TelemetryEvent(
				Manager->GetTelemetryManager()->FetchAddEventId(), 
				Manager->GetTelemetryManager()->GetClientId(), 
				TelemetryEvent::Action::ModuleLoad,
				GetCurrentProcessId(), 
				StrHelper::WStringToString(FullDllName), 
				0));
		}
		    
	}
	else if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_UNLOADED)
	{
		if (StrHelper::ContainsStrW(L"\\windows\\system32\\secur32.dll", FullDllName) || StrHelper::ContainsStrW(L"\\windows\\system32\\sspicli.dll", FullDllName))
			return;

		{
			//std::lock_guard<std::mutex> lock(DM->pImpl->LoadedModulesMutex);
			auto& vec = Manager->pImpl->LoadedModules;
			vec.erase(std::remove(vec.begin(), vec.end(), FullDllName), vec.end());
		}

		if (Manager->UsingTelemetry() && Manager->TelemetryManager != nullptr)
		{
			Manager->TelemetryManager->LogEvent(TelemetryEvent(
				Manager->GetTelemetryManager()->FetchAddEventId(), 
				Manager->GetTelemetryManager()->GetClientId(), 
				TelemetryEvent::Action::ModuleUnload,
				GetCurrentProcessId(), 
				StrHelper::WStringToString(FullDllName), 
				0));
		}	    
	}
}

/**
 * @brief   Checks the queue of modules for if they are code-signed or not
 * @param   `DM`  pointer to the DetectionManager object containing the queue
 * @return  None
 */
void DetectionManager::Impl::CheckDLLSignatures(DetectionManager* DM)
{
	if (DM == nullptr)
	{
#ifdef _LOGGING_ENABLED

#endif
		return;
	}

	auto& impl = *DM->pImpl;

	std::unique_lock<std::mutex> lock(impl.DLLVerificationQueueMutex);

	while (!impl.bStopRequested.load())
	{
		impl.DLLQueueCV.wait(lock, [&]  //sleep until new work comes in or shut down
			{
				return !impl.DLLVerificationQueue.empty() || impl.bStopRequested.load();
			});

		if (impl.bStopRequested.load())
			break;

		auto FullDllName = impl.DLLVerificationQueue.front();
		impl.DLLVerificationQueue.pop();
		lock.unlock(); //release the lock for possibly long-running sig check

		if (!impl.UnsignedLoadedModules.count(FullDllName) && !impl.PassedCertCheckModules.count(FullDllName))
		{
			if (!Authenticode::HasSignature(FullDllName.c_str(), TRUE))
			{
				std::lock_guard<std::mutex> lock(impl.ModuleListMutex);

				if (impl.UnsignedLoadedModules.count(FullDllName) == 0)
					impl.UnsignedLoadedModules.insert(FullDllName);

				DetectionResult DR(DetectionFlags::LOADED_UNSIGNED_MODULE, StrHelper::WStringToString(FullDllName), GetCurrentProcessId(), DetectionSeverity::Warning);
				DM->AddDetected(DR);
				wprintf(L"Module was unsigned: %s\n", FullDllName.c_str());
			}
			else
			{
				std::lock_guard<std::mutex> lock(impl.PassedCertCheckListMutex);

				if (impl.PassedCertCheckModules.count(FullDllName) == 0)
					impl.PassedCertCheckModules.insert(FullDllName);
			}
		}

		lock.lock(); //take back the lock
	}
}



void to_json(json& j, const DetectionRule& dr)
{
	j = json{
		{"enabled", dr.bEnabled},
		{"id", dr.id},
		{"label", dr.Label},
		{"severity", dr.Severity},
		{"is_process_scan", dr.bIsProcessScan},
		{"is_one_time_scan", dr.bIsOneTimeScan},
		{"is_self_process_scan", dr.bIsSelfProcessScan},
		{"is_system_config_scan", dr.bIsSystemConfigScan},
		{"force_shutdown_on_flag", dr.bForceShutdownOnFlag},
		{"terminate_offending_process", dr.bTerminateOffendingProcess},
		{"is_continuous_scan", dr.bContinuousScan},
		{"artifacts", dr.Artifacts},
		{"names", dr.Names}
	};
}

inline void from_json(const nlohmann::json& j, DetectionRule& rule)
{
	j.at("enabled").get_to(rule.bEnabled);
	j.at("id").get_to(rule.id);
	j.at("label").get_to(rule.Label);
	j.at("severity").get_to(rule.Severity);
	j.at("is_process_scan").get_to(rule.bIsProcessScan);
	j.at("is_one_time_scan").get_to(rule.bIsOneTimeScan);
	j.at("is_self_process_scan").get_to(rule.bIsSelfProcessScan);
	j.at("is_system_config_scan").get_to(rule.bIsSystemConfigScan);
	j.at("force_shutdown_on_flag").get_to(rule.bForceShutdownOnFlag);
	j.at("terminate_offending_process").get_to(rule.bTerminateOffendingProcess);

	if (j.contains("is_continuous_scan") && !j["is_continuous_scan"].is_null())
		j["is_continuous_scan"].get_to(rule.bContinuousScan);

	if (j.contains("artifacts") && !j["artifacts"].is_null())
		j["artifacts"].get_to(rule.Artifacts);

	if (j.contains("names") && !j["names"].is_null())
		j["names"].get_to(rule.Names);
}