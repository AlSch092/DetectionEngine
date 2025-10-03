// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include <Windows.h>

class SecureBootScan : public IDetector //one-shot check
{
private:
	bool bSecureBootEnabled = false;

public:
    SecureBootScan() = default;
    ~SecureBootScan() = default;

	SecureBootScan(__in const DetectionRule& rule)
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

		HKEY hKey;
		LONG lResult;
		DWORD dwSize = sizeof(DWORD);
		DWORD dwValue = 0;
		const char* registryPath = "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State";
		const char* valueName = "UEFISecureBootEnabled";

		lResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE, registryPath, 0, KEY_READ, &hKey);

		if (lResult != ERROR_SUCCESS)
		{
#ifdef _LOGGING_ENABLED
			printf("Failed to read registry key @ SecureBootScan::Run: %d\n", GetLastError());
#endif
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		lResult = RegQueryValueExA(hKey, valueName, NULL, NULL, (LPBYTE)&dwValue, &dwSize);

		if (lResult != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}
		
		if (dwValue == 0)
		{
			result.Flag = DetectionFlags::SECURE_BOOT_DISABLED;
			result.ProcessId = 0;
			bSecureBootEnabled = false;
		}

		RegCloseKey(hKey);
        return result;
    }
};