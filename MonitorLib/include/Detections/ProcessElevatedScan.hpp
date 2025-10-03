// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include <Windows.h>

class ProcessElevatedScan : public IDetector //one-shot check
{
private:
	bool bIsProcessElevated = false;

public:
	ProcessElevatedScan() = default;
	~ProcessElevatedScan() = default;

	ProcessElevatedScan(__in const DetectionRule& rule)
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

		BOOL isAdmin = FALSE;
		PSID adminGroup = NULL;

		// Allocate and initialize a SID for the administrators group
		SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
		if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
		{
			CheckTokenMembership(NULL, adminGroup, &isAdmin);
			FreeSid(adminGroup);
		}
		else
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		bIsProcessElevated = isAdmin;

		if (bIsProcessElevated)
		{
			result.Flag = DetectionFlags::PROCESS_NOT_ADMIN;
			result.ProcessId = GetCurrentProcessId();
		}

		return result;
	}
};