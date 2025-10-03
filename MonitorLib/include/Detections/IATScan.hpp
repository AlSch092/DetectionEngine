// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include <Windows.h>
#include "../ProcessHelper.hpp"

struct ImportFunction
{
	HMODULE Module;
	std::string AssociatedModuleName;
	std::string FunctionName;
	uintptr_t AddressToFuncPtr;
	uintptr_t AddressOfData;
	uintptr_t FunctionPtr;
};

/**
* @brief The IATScan class checks whether the Import Address Table of the current process is hooked or not.
* Remote process scanning will be added in future releases.
*
*/
class IATScan : public IDetector //one-shot check
{
private:
	bool bIsIATModified = false;
	bool bIsFixedTargetProcessId = false;

	std::list<ImportFunction> GetIATEntries(const std::string& module)
	{
		if (module.empty() || module == "ntdll.dll" || module == "win32u.dll")
			return {};

		HMODULE hModule = GetModuleHandleA(module.c_str());

		if (hModule == NULL)
		{
#if _LOGGING_ENABLED
			std::cerr << "Couldn't fetch module handle @ Process::GetIATEntries " << std::endl;
#endif
			return {};
		}

		IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;

		if (dosHeader == nullptr)
		{
#if _LOGGING_ENABLED
			std::cerr << "Couldn't fetch dosHeader @ Process::GetIATEntries " << std::endl;
#endif
			return {};
		}

		IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
		IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		{
			//bIsIATModified = true;
#if _LOGGING_ENABLED
			std::cerr << "DataDirectory (IMAGE_DIRECTORY_ENTRY_IMPORT) size was 0 for " << module << std::endl;
#endif
			return {};
		}

		std::list<ImportFunction> importList;

		while (importDesc->OriginalFirstThunk != 0  || importDesc->FirstThunk != 0)
		{
			if (!IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
				break;

			const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);

			if (dllName == nullptr)
				continue;

			IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->FirstThunk);

			if (iat != nullptr)
			{
				while (iat->u1.Function != 0)
				{
					ImportFunction import;
                    import.AssociatedModuleName = dllName;
                    import.Module = GetModuleHandleA(dllName);
                    import.AddressOfData = (uintptr_t)iat->u1.AddressOfData;
                    import.FunctionPtr = (uintptr_t)iat->u1.Function; //actual IAT pointer
					import.AddressToFuncPtr = (uintptr_t)&iat->u1.Function;
					importList.push_back(import);
					iat++;
				}
			}

			importDesc++;
		}

		return importList;
	}

	bool DoesIATContainHooked()
	{
		bool isIATHooked = false;

		if (bIsIATModified) //IAT info was stripped from binary?
		{
			return true;
		}

		auto modules = ProcessHelper::GetLoadedModules();

		if (modules.size() == 0)
		{
			throw std::runtime_error("Module size was 0!");
		}

		for (auto mod : modules)
		{
			std::list<ImportFunction> IATFunctions = GetIATEntries(StrHelper::WStringToString(mod.baseName));

			for (ImportFunction IATEntry : IATFunctions)
			{
				DWORD moduleSize = ProcessHelper::GetModuleSize(IATEntry.Module);

				bool FoundIATEntryInModule = false;

				if (moduleSize != 0)  //some IAT functions in k32 can point to ntdll (forwarding), thus we have to compare IAT to each other whitelisted DLL range
				{
					for (auto mod : modules)
					{
						uintptr_t LowAddr = (uintptr_t)mod.dllInfo.lpBaseOfDll;
						uintptr_t HighAddr = LowAddr + mod.dllInfo.SizeOfImage;

						if (IATEntry.FunctionPtr >= LowAddr && IATEntry.FunctionPtr < HighAddr) //each IAT entry needs to be checked thru all loaded ranges
						{
							FoundIATEntryInModule = true;
						}
					}

					if (!FoundIATEntryInModule) //iat points to outside loaded module
					{
#ifdef _LOGGING_ENABLED
						std::cout << "Hooked IAT detected: " << IATEntry.AssociatedModuleName.c_str() << " at: " << IATEntry.FunctionPtr << std::endl;
#endif

						isIATHooked = true;
						bIsIATModified = true;
						break;
					}
				}
				else //error, we shouldnt get here!
				{
#if _LOGGING_ENABLED
					std::cerr << " Couldn't fetch  module size @ Detections::DoesIATContainHooked" << std::endl;
#endif
					return FALSE;
				}
			}
		}

		return isIATHooked;
	}

public:
	IATScan() = default;
	~IATScan() = default;

	IATScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);
	}

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

		if (DoesIATContainHooked())
		{
			result.Flag = DetectionFlags::BAD_IAT;
			result.ProcessId = GetCurrentProcessId();
		}

		return result;
	}
};