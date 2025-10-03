// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include <Windows.h>

/**
* @brief The DriverSignatureEnforcementScan class checks the system configuration to see whether 'test mode' or driver signature enforcement is enabled or not.
*
*/
class DriverSignatureEnforcementScan : public IDetector
{
private:
    bool bIsTestSigningModeEnabled = false;

    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemCodeIntegrity = 103
    } SYSTEM_INFORMATION_CLASS;

    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION
    {
        ULONG Length;
        ULONG CodeIntegrityOptions;
    } SYSTEM_CODEINTEGRITY_INFORMATION;

public:
    DriverSignatureEnforcementScan() = default;
    ~DriverSignatureEnforcementScan() = default;

    DriverSignatureEnforcementScan(__in const ScanIds id)
    {
        this->SetId(id);
    }

    DriverSignatureEnforcementScan(__in const DetectionRule& rule)
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

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

        if (ntdll == NULL)
        {
            result.Flag = DetectionFlags::EXECUTION_ERROR;
            return result;
        }

        NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(ntdll, "NtQuerySystemInformation");

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
            if (sci.CodeIntegrityOptions & 0x02) //CODEINTEGRITY_OPTION_TESTSIGN
            {
                result.Flag = DetectionFlags::TEST_SIGNING_MODE;
                result.ProcessId = 0;
                bIsTestSigningModeEnabled = true;
            }
                
        }

        return result;
    }
};