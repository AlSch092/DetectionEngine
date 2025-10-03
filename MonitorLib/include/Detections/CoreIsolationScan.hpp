// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include <Windows.h>


/**
* @brief The HVCIScan checks the system configuration to see whether hypervisor code integrity is enabled or not (core isolation).
*
*/
class HVCIScan : public IDetector
{
private:
	bool bIsCoreIsolationEnabled = false;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemCodeIntegrity = 103
	} SYSTEM_INFORMATION_CLASS;

	const int CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED = 0x400;

	typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
	{
		ULONG Length;
		ULONG CodeIntegrityOptions;
	} SYSTEM_CODEINTEGRITY_INFORMATION;

public:
    HVCIScan() = default;
    ~HVCIScan() = default;

	HVCIScan(__in const ScanIds id)
	{
		this->SetId(id);
	}

	HVCIScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);
	}

    DetectionResult Run() override
    {
		if (!this->Enabled())
			return {};

        DetectionResult result;
		result.Flag = DetectionFlags::NONE;
		this->RunCount++;

		HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");

		if (hNtDll == NULL)
		{
			hNtDll = LoadLibraryW(L"ntdll.dll");

			if (!hNtDll)
			{
				result.Flag = DetectionFlags::EXECUTION_ERROR;
				return result;
			}
		}

		NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hNtDll, "NtQuerySystemInformation");

		if (!NtQuerySystemInformation)
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		SYSTEM_CODEINTEGRITY_INFORMATION sci = { sizeof(sci), 0 };

		ULONG flags = 0;
		NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemCodeIntegrity, &sci, sizeof(sci), NULL);

		if (status == 0)
		{
			if (!(sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED))
			{
				result.Flag = DetectionFlags::HVCI_DISABLED;
				result.ProcessId = 0;
				bIsCoreIsolationEnabled = true;
			}
		}

        return result;
    }
};