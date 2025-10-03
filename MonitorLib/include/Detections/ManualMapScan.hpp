// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../CapstoneHelper.hpp"

/**
* @brief The ManualMappedModuleScan class checks for manually mapped modules within a specific process.
*
*/
class ManualMappedModuleScan : public IDetector
{
private:
    std::vector<CapstoneData> MappedRegionAddresses; //todo: clear this out after its reported to the backend servers

    std::unique_ptr<CapstoneHelper> capstone = nullptr;

	bool bIsFixedTargetProcessId = false;

public:

	ManualMappedModuleScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);

		try
		{
			capstone = std::make_unique<CapstoneHelper>();
		}
		catch (const std::bad_alloc& ex)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Failed to create capstone helper: " << ex.what() << std::endl;
#endif
		}
	}

	~ManualMappedModuleScan() = default;

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
		this->RunCount++;

        if (this->ProcessId <= 4 && !this->ProcessId == GetCurrentProcessId())
        {
            return result;
        }

		HMODULE hMods[1024]; //is filled by EnumProcessModulesEx
		DWORD cbNeeded;

		std::vector<ModuleInfoMini> modules; //store each module's information such as size & base address
		std::vector<CapstoneData> SuspiciousRegions; //this list is addresses which may be either: PE headers, .text or .rdata sections.

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->ProcessId);

		if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL)
		{
#if _LOGGING_ENABLED
			//Logger::logf(Err, "Failed to open process handle of pid %d @ DetectManualMapping. Error %d", pid, GetLastError());
#endif
			return {};
		}

		if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) 	//list of all the modules in the process
		{
			for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				MODULEINFO modInfo;
				if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
				{
					modules.emplace_back(ModuleInfoMini { (uintptr_t)modInfo.lpBaseOfDll , modInfo.SizeOfImage });
				}
			}
		}

		MEMORY_BASIC_INFORMATION mbi;
		uintptr_t CurrentRegionAddr = 0;  //starting address to scan from
#ifdef _M_X64
		uintptr_t userModeLimit = 0x00007FFFFFFFFFFF; 	// 64-bit user-mode memory typically ends around 0x00007FFFFFFFFFFF
#else
		uintptr_t userModeLimit = 0x7FFFFFFF;
#endif
		//loop through all memory regions until userModeLimit
		while ((uintptr_t)CurrentRegionAddr < userModeLimit && VirtualQueryEx(hProcess, (LPCVOID)CurrentRegionAddr, &mbi, sizeof(mbi)) == sizeof(mbi))
		{
			if (mbi.State != MEM_COMMIT) //skip memory regions that are reserved or free (only care about committed memory)
			{
				CurrentRegionAddr += mbi.RegionSize;
				continue;
			}

			// has executable permissions?
			if (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE))
			{
				//part of a known module?
				if (ProcessHelper::IsAddressInModule(modules, (uintptr_t)mbi.BaseAddress))
				{
					CurrentRegionAddr += mbi.RegionSize; //legitimate module, skip
					continue;
				}

				unsigned char buffer[512]{ 0 };

				if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, sizeof(buffer), NULL))
				{
					if (ProcessHelper::IsPEHeader(buffer)) //if the PE header is deleted, this won't detect it
					{
						CapstoneData info = this->capstone->GetInstructionsFromBytes(buffer, sizeof(buffer), (uintptr_t)mbi.BaseAddress, 8);
						SuspiciousRegions.push_back(info);

						CurrentRegionAddr += mbi.RegionSize;
						continue; //keep scanning for any more detected regions
					}
					else //check for possible erased headers with manual mapping, this will be the trickest thing in usermode to detect
					{
						PSAPI_WORKING_SET_EX_INFORMATION wsInfo;
						wsInfo.VirtualAddress = mbi.BaseAddress;

						bool foundPossibleErasedHeaderModule = true;

						if (QueryWorkingSetEx(hProcess, &wsInfo, sizeof(wsInfo)))
						{
							if (wsInfo.VirtualAttributes.Valid)
							{
								if (!wsInfo.VirtualAttributes.Shared)  // If not shared, it's likely private
								{
									bool foundPossibleSection = false;
									unsigned char buffer_possibleTextSection[128]{ 0 };

									//todo: make some better way than just using a hardcoded offset , since this can be changed with section alignment
									const uintptr_t defaultTextSectionOffset = 0x1000; //this could easily change with a more advanced manual mapper or different section alignment.. bleh
									uintptr_t possibleTextSectionAddress = (uintptr_t)(mbi.BaseAddress) + defaultTextSectionOffset;

									if (ReadProcessMemory(hProcess, (LPCVOID)possibleTextSectionAddress, buffer_possibleTextSection, sizeof(buffer_possibleTextSection), NULL))
									{
										for (int i = 0; i < sizeof(buffer_possibleTextSection) - 4; i++) //todo: switch this to using capstone and parse instructions
										{
											if (buffer_possibleTextSection[i] != 0 && buffer_possibleTextSection[i + 1] != 0 && buffer_possibleTextSection[i + 2] != 0 && buffer_possibleTextSection[i + 3] != 0)
											{
												foundPossibleSection = true;
												break;
											}
										}
									}

									if (foundPossibleSection) //this will be the most likely spot which gives false positives, but its also the trickest to detect
									{
										CapstoneData info = this->capstone->GetInstructionsFromBytes(buffer_possibleTextSection, sizeof(buffer_possibleTextSection), possibleTextSectionAddress, 8);

										//std::cout << "[DETECTION] possible .text section of erased-header manual mapped module at  " << std::hex << possibleTextSectionAddress << std::endl;
										SuspiciousRegions.push_back(info);
									}
								}
							}
						}
					}
				}
			}

			CurrentRegionAddr += mbi.RegionSize;
		}

		CloseHandle(hProcess);
        return result;
    }
};