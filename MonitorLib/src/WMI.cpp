//By Alsch092 @ Github
#include "../include/WMI.hpp"

/**
 * @brief  Initaillizes COM service using CoInitializeEx
 * @details  Needs to be called as early as possible after program startup, one time
 * 
 * @return true/false  if CoInitializeEx succeeded with COINIT_MULTITHREADED
 *
 * @usage
 * BOOL comSuccess = WMI::InitializeCOM();
 */
bool WMI::InitializeCOM()
{
	if (this->bInitializedCOM)
		return true;

	// First, initialize COM on this thread (service main thread)
	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr) && hr != S_FALSE && hr != RPC_E_CHANGED_MODE) 
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "CoInitializeSecurity failed @ InitializeCOM critical error:: " << hr << std::endl;
#endif
		return false; // hard failure
	}

	// Early in ServiceMain (before threads / DLL calls):
	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IDENTIFY,nullptr, EOAC_NONE, nullptr);
	
	if (hr == RPC_E_TOO_LATE) 
		hr = S_OK;  // someone beat you to it; fine

	if (FAILED(hr)) 
	{ 
		/* log & abort startup */ 
#ifdef _LOGGING_ENABLED
		std::cerr << "CoInitializeSecurity failed! critical error: : " << hr << std::endl;
#endif
		return false;
	}

	this->bInitializedCOM = true;

	return true;
}

/**
 * @brief  Sets up the WMI service, connects to the CIMV2 namespace server
 *
 * @return HRESULT indicating status 
 *
 * @usage
 *  HRESULT hres = WMI::ConnectToWMI(DetectionManager->wmiInterface);
 */
HRESULT WMI::ConnectToWMI(ComPtr<IWbemServices>& svc)
{
	HRESULT hr = EnsureComOnThisThread();

	if (FAILED(hr)) 
		return hr;

	const wchar_t* ns = L"ROOT\\CIMV2";

	ComPtr<IWbemLocator> loc;

	hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&loc));

	if (FAILED(hr)) 
		return hr;

	hr = loc->ConnectServer(BSTR(ns), nullptr, nullptr, 0, 0, 0, 0, &svc);

	if (FAILED(hr)) 
		return hr;

	hr = CoSetProxyBlanket(svc.Get(),
		RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,   // stronger default for services
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr, EOAC_NONE);

	this->wmiInterface = svc;

	return hr;
}

/**
 * @brief Checks code signature of a file through either embedded signature or catalog signature
 *
 * @param filePath The file path to the executable or DLL to check
 * @param checkEndCertRevoked Whether or not to check if the end certificate is revoked
 *
 * @return true/false if WinMgmt service is running or not
 *
 * @usage
 * bool isWMIRunning = WMI::IsWMIServiceRunning();
 */
bool WMI::IsWMIServiceRunning()
{
	SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
	{
#if _LOGGING_ENABLED
		std::cerr << "Failed to open Service Control Manager @ Services::IsWMIServiceRunning: " << GetLastError() << std::endl;
#endif
		return false;
	}

	SC_HANDLE hService = OpenServiceA(hSCManager, "Winmgmt", SERVICE_QUERY_STATUS);
	if (!hService)
	{
#if _LOGGING_ENABLED
		std::cerr <<  "Failed to open WMI service  @ Services::IsWMIServiceRunning: " << GetLastError() << std::endl;
#endif
		CloseServiceHandle(hSCManager);
		return false;
	}

	SERVICE_STATUS status;
	bool isRunning = false;

	if (QueryServiceStatus(hService, &status))
	{
		isRunning = (status.dwCurrentState == SERVICE_RUNNING);
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return isRunning;
}


/**
 * @brief Starts the WMI service for use in process creation callbacks
 *
 *
 * @return true/false If WMI service was started successfully
 *
 * @usage
 * bool WMIStartSuccess = WMI::StartWMIService();
 */
bool WMI::StartWMIService()
{
	bool successStart = false;

	if (IsWMIServiceRunning())
	{
#if _LOGGING_ENABLED
		std::cerr << "WMI service is already running. @ Services::StartWMIService\n";
#endif
		return true;
	}

	SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!hSCManager)
	{
#if _LOGGING_ENABLED
		std::cerr << "Failed to open Service Control Manager @ Services::StartWMIService: " << GetLastError() << std::endl;
#endif
		return false;
	}

	SC_HANDLE hService = OpenService(hSCManager, L"Winmgmt", SERVICE_START);
	if (!hService)
	{
#if _LOGGING_ENABLED
		std::cerr << "Failed to open WMI service @ Services::StartWMIService: " << GetLastError() << std::endl;
#endif
		CloseServiceHandle(hSCManager);
		return false;
	}

	if (!StartService(hService, 0, nullptr))
	{
#if _LOGGING_ENABLED
		std::cerr << "Failed to start WMI Service @ Services::StartWMIService: " << GetLastError() << std::endl;
#endif
		successStart = false;
	}
	else
	{
#if _LOGGING_ENABLED
		std::cerr << "WMI service started successfully @ Services::StartWMIService\n";
#endif
		successStart = true;
	}

	// Cleanup
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	return successStart;
}

