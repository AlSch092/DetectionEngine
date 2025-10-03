// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../ProcessHelper.hpp"
#include "../StrHelper.hpp"
#include "../Authenticode.hpp"
#include <list>
#include <mutex>
#include <unordered_set>

struct DetectedHandleProcInfo
{
	std::wstring Name;
	uint32_t Pid = 0;
	USHORT h = 0; //as per SYSTEM_HANDLE structure

	bool operator==(const DetectedHandleProcInfo& other) const noexcept
	{
		return h == other.h && Pid == other.Pid;
	}
};

//not a one-shot scan
//should occur outside of proc creation callback
class ProcessHandlesScan : public IDetector
{
public:
	ProcessHandlesScan() = default;

	~ProcessHandlesScan() = default;

	ProcessHandlesScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);

		for (const auto& str : rule.Artifacts) //add whitelisted processes
		{
			this->AddToWhitelist(str);
		}
	}

	void AddToWhitelist(__in const std::wstring& whitelistedProcName)
	{
		if (whitelistedProcName.empty())
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "whitelistedProcName was empty @ AddToWhitelist\n";
#endif
			return;
		}

		std::wstring whitelistedProcNameLower = StrHelper::ToLower(whitelistedProcName);

		std::lock_guard<std::mutex> lock(WhitelistMutex);

		if (std::find(WhitelistedProcesses.begin(), WhitelistedProcesses.end(), whitelistedProcNameLower) == WhitelistedProcesses.end())
			WhitelistedProcesses.push_back(whitelistedProcNameLower);
	}

	void AddToWhitelist(__in const std::string& whitelistedProcName)
	{
		if (whitelistedProcName.empty())
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "whitelistedProcName was empty @ AddToWhitelist\n";
#endif
			return;
		}

		std::wstring whitelistedProcNameW = StrHelper::ToLower(StrHelper::StringToWString(whitelistedProcName));

		std::lock_guard<std::mutex> lock(WhitelistMutex);

		if (std::find(WhitelistedProcesses.begin(), WhitelistedProcesses.end(), whitelistedProcNameW) == WhitelistedProcesses.end())
			WhitelistedProcesses.push_back(whitelistedProcNameW);
	}

	auto GetDetectedProcessList() const { return this->DetectedProcesses; }

	DetectionResult Run() override
	{
		if (!this->Enabled())
			return {};

		DetectionResult result;
		result.Flag = DetectionFlags::NONE;
		DetectedProcesses.clear();
		this->RunCount++;

		auto handleList = DetectOpenProcessHandlesToProcess(GetCurrentProcessId());

		for (const auto& handle : handleList)
		{
			if (!handle.ReferencingOurProcess)
				continue;

			std::wstring procPath = ProcessHelper::GetProcessPathByPID(handle.ProcessId);

			if (procPath.empty())
			{
				//log error and continue?
				continue;
			}

			OutputDebugStringW(L"Found open process handle to our process from: ");
			OutputDebugStringW(procPath.c_str());
			OutputDebugStringW(L"\n");

			std::wstring procName = procPath.substr(procPath.find_last_of(L'\\') + 1, procPath.length() - procPath.find_last_of(L'\\') - 1);

			OutputDebugStringW(L"procName: ");
			OutputDebugStringW(procName.c_str());
			OutputDebugStringW(L"\n");

			auto pname = StrHelper::ToLower(procName);

			if (pname.empty())
			{
#ifdef _LOGGING_ENABLED
				std::cerr << "pname was empty @ ProcessHandlesScan::Run()\n";
#endif
			}

			DetectedHandleProcInfo dpi{ procPath, handle.ProcessId, handle.Handle };

			// 1) Skip if already detected before
			bool bAlreadyDetected = false;
			for (const auto& detected : DetectedProcesses)
			{
				if (dpi == detected)
				{
					bAlreadyDetected = true;
					break;
				}
			}
			if (bAlreadyDetected)
				continue;

			// 2) Check if already cached as unsigned
			{
				std::lock_guard<std::mutex> lock(UnsignedCacheMutex);
				if (UnsignedProcessCache.find(procPath) != UnsignedProcessCache.end())
				{
					// already known bad
					result.Flag = DetectionFlags::OPEN_PROCESS_HANDLES;
					result.ProcessId = handle.ProcessId;
					result.Description += std::to_string(handle.ProcessId) + "=" + StrHelper::WStringToString(procPath) + ",";
					DetectedProcesses.emplace_back(dpi);
					continue;
				}
			}

			// 3) Whitelist check
			bool bWhitelisted = false;
			{
				std::lock_guard<std::mutex> lock(WhitelistMutex);
				bWhitelisted = (std::find(WhitelistedProcesses.begin(),
					WhitelistedProcesses.end(),
					pname) != WhitelistedProcesses.end());
			}

			// 4) Signature check if not whitelisted
			if (!bWhitelisted)
			{
				if (Authenticode::HasSignature(procPath.c_str(), TRUE)) //should be possibly threaded
					bWhitelisted = true;
			}

			OutputDebugStringW(L"Handle not whitelisted: detected open process handle to us");

			// 5) If still not whitelisted, record detection and cache unsigned
			if (!bWhitelisted)
			{
				{
					std::lock_guard<std::mutex> lock(UnsignedCacheMutex);
					UnsignedProcessCache.insert(procPath);
				}

				result.Flag = DetectionFlags::OPEN_PROCESS_HANDLES;
				result.ProcessId = handle.ProcessId;
				result.Description += std::to_string(handle.ProcessId) + "=" + StrHelper::WStringToString(procPath) + ",";
				{
					std::lock_guard<std::mutex> lock(DetectedListMutex);
					DetectedProcesses.emplace_back(dpi);
				}
			}
		}

		if (!result.Description.empty() && result.Description.back() == ',')
			result.Description.pop_back();

		return result;
	}

private:
	std::list<std::wstring> WhitelistedProcesses; //whitelisted procs with open handles to our process also need to be cert checked
	std::list<DetectedHandleProcInfo> DetectedProcesses; //processes with open process handles to our process

	std::unordered_set<std::wstring> UnsignedProcessCache;
	std::mutex UnsignedCacheMutex;

	std::mutex WhitelistMutex;
	std::mutex DetectedListMutex;

	std::vector<ProcessHelper::SYSTEM_HANDLE> GetAllOpenHandles()
	{
		typedef enum _SYSTEM_INFORMATION_CLASS
		{
			SystemHandleInfo = 16
		} SYSTEM_INFORMATION_CLASS;

		typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

		HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");

		if (hNtDll == NULL)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Failed to fetch ntdll module address @ IsMachineAllowingSelfSignedDrivers. Error code: " << GetLastError() << std::endl;
#endif
			return {};
		}

		NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hNtDll, "NtQuerySystemInformation");

		if (!NtQuerySystemInformation)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Could not get NtQuerySystemInformation function address @ Handles::GetHandles" << std::endl;
#endif
			return {};
		}

		ULONG bufferSize = 0x10000;
		PVOID buffer = nullptr;
		NTSTATUS status = 0;

		do
		{
			buffer = malloc(bufferSize);

			if (!buffer)
			{
#ifdef _LOGGING_ENABLED
				std::cerr << "Memory allocation failed @ Handles::GetHandles" << std::endl;
#endif
				return {};
			}

			status = NtQuerySystemInformation(SystemHandleInfo, buffer, bufferSize, &bufferSize);

			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				free(buffer);
				bufferSize *= 2;
			}
			else if (!(((NTSTATUS)(status)) >= 0))
			{
#ifdef _LOGGING_ENABLED
				std::cerr << "NtQuerySystemInformation failed @ Handles::GetHandles" << std::endl;
#endif
				free(buffer);
				return {};
			}
		} while (status == STATUS_INFO_LENGTH_MISMATCH);

		ProcessHelper::PSYSTEM_HANDLE_INFORMATION handleInfo = (ProcessHelper::PSYSTEM_HANDLE_INFORMATION)buffer;

		std::vector<ProcessHelper::SYSTEM_HANDLE> handles;
		handles.reserve(handleInfo->HandleCount);

		DWORD ourPid = GetCurrentProcessId();

		for (int i = 0; i < handleInfo->HandleCount; i++)
		{
			if (handleInfo->Handles[i].ProcessId <= 4 || handleInfo->Handles[i].ProcessId == ourPid) //skip over our own handles and process handles
			{
				continue;
			}

			//if (handleInfo->Handles[i].ObjectTypeNumber != 7) //optionally, also skip if its not a process handle (for example, obtained from OpenProcess). however we can't guarantee it will be 7 across diff windows versions
			//{
			//    continue;
			//}

			ProcessHelper::SYSTEM_HANDLE handle = handleInfo->Handles[i];
			handles.push_back(handle);
		}

		free(buffer);
		return handles;
	}

	std::vector<ProcessHelper::SYSTEM_HANDLE> DetectOpenProcessHandlesToProcess(__in const DWORD pid) //pid should be our process id (or GetCurrentProcessId())
	{
		auto handles = GetAllOpenHandles();
		std::vector<ProcessHelper::SYSTEM_HANDLE> handlesToUs;

		for (auto& handle : handles)
		{
			if (handle.ProcessId != pid) //ignore target pid handles
			{
				if (handle.ProcessId <= 4)
				{
					continue;
				}

				HandleGuard processHandle = HandleGuard(OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId));

				if (processHandle.isValid())
				{
					HANDLE duplicatedHandle = INVALID_HANDLE_VALUE;

					if (DuplicateHandle(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &duplicatedHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
					{
						if (GetProcessId(duplicatedHandle) == pid)
						{
							OutputDebugStringA("Handle referencing our process: ");
							OutputDebugStringA(std::to_string(handle.Handle).c_str());
							OutputDebugStringA("\n");

							handle.ReferencingOurProcess = true;
							handlesToUs.push_back(handle);
						}
						else
						{
							handle.ReferencingOurProcess = false;
						}

						if (duplicatedHandle != INVALID_HANDLE_VALUE)
							CloseHandle(duplicatedHandle);
					}
				}
				else
				{
					//#ifdef _LOGGING_ENABLED
					//std::cerr << "Couldn't open process with id " << pid << " @ Handles::DetectOpenHandlesToProcess" << std::endl;
				   //#endif
					continue;
				}
			}
		}

		return handlesToUs;
	}
};