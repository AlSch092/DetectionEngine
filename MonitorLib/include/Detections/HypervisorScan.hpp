// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include <Windows.h>
#include <intrin.h>

/**
* @brief The HypervisorScan class checks whether the current system environment is run under a hypervisor or not
*
*/
class HypervisorScan : public IDetector //one-shot check
{
private:
	bool bHypervisorRunning = false;
	std::string HypervisorVendor;

	const bool IsHypervisorPresent()
	{
		int cpuInfo[4] = { 0 };
		__cpuid(cpuInfo, 1);
		return (cpuInfo[2] & (1 << 31)) != 0;     // bit 31 of ECX = 1 means a hypervisor is present
	}

	/*
	  GetHypervisorVendor - check vendor of hypervisor, if present
	     Common results:
	          "Microsoft Hv"	Hyper-V
	          "KVMKVMKVM"	KVM
	          "VMwareVMware"	VMware
	          "XenVMMXenVMM"	Xen
	          "prl hyperv"	Parallels
	          "VBoxVBoxVBox"	VirtualBox
	*/
	const std::string GetHypervisorVendor()
	{
		int cpuInfo[4] = { 0 };

		__cpuid(cpuInfo, 0x40000000);

		char vendor[13] = { 0 };

		memcpy(vendor, &cpuInfo[1], 4);
		memcpy(vendor + 4, &cpuInfo[2], 4);
		memcpy(vendor + 8, &cpuInfo[3], 4);

		return std::string(vendor);
	}

public:
	HypervisorScan() = default;
	~HypervisorScan() = default;

	HypervisorScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);
	}

	const bool FoundHypervisor() { return this->IsHypervisorPresent(); }
	const std::string GetVendor() { return this->GetHypervisorVendor(); }

	DetectionResult Run() override
	{
		if (!this->Enabled())
			return {};

		DetectionResult result;
		result.Flag = DetectionFlags::NONE;
		this->RunCount++;

		if (IsHypervisorPresent())
		{
			bHypervisorRunning = true;
			HypervisorVendor = GetHypervisorVendor();
			result.Flag = DetectionFlags::HYPERVISOR;
			result.Description = HypervisorVendor;
			result.ProcessId = 0;
		}

		return result;
	}
};