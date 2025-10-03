//By Alsch092 @ Github
#pragma once
#include <Windows.h>
#include <string>
#include <unordered_map>

extern "C" NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation); //used in GetWindowsMajorVersion

enum WindowsVersion
{									//Major,Minor :
	Windows2000 = 50,				//5,0
	WindowsXP = 51,			        //5,1
	WindowsXPProfessionalx64 = 52,	//5,2
	WindowsVista = 60,				//6,0
	Windows7 = 61,					//6,1
	Windows8 = 62,					//6,2
	Windows8_1 = 63,				//6,3
	Windows10 = 100,					//10
	Windows11 = 110,					//10  -> build number changes 
	ErrorUnknown = 0
};

enum WindowsBuilds
{
	//Win10
	b_10240 = 10240, // 1507 (2015): Build 10240, supported until October 14, 2025 Threshold 1
	b_10586 = 10586, //Threshold 2
	b_14393 = 14393, // 1607 (2016): Build 14393, supported until October 13, 2026.  Redstone 1
	b_15063 = 15063, //redstone 2  1703
	b_16299 = 16299, //Redstone 3  1709
	b_17134 = 17134, //Redstone 4
	b_17763 = 17763, // 1809 (2019): Build 17763, supported until January 9, 2029.   Redstone 5

	b_18362 = 18362, //1903
	b_18363 = 18363, //1909
	b_19041 = 19041, //2004
	b_19042 = 19042, //20H2
	b_19043 = 19043, //21H1
	b_19044 = 19044, // 21H2 (2021): Build 19044, supported until January 12, 2027 (mainstream).
	b_19045 = 19045, // 22H2 (build 19045), which will be supported until October 14, 2025 (final version)

	//Win11
	b_21996 = 21996,  //leaked Win11 insider beta
	b_22000 = 22000,
	b_22621 = 22621, //22H2 (2022): Build 22621, supported until October 2024 (Home/Pro) and October 2025 (Enterprise/Education)
	b_22631 = 22631, //23H2 (2023): Build 22631, supported until November 2025 (Home/Pro) and November 2026 (Enterprise/Education).
	b_26100 = 26100, //Mainstream support for 24H2 ends on October 13, 2026 (Home/Pro) and October 12, 2027 (Enterprise/Education).

	b_Unknown = 0
};

class WindowsBuildChecker
{
public:
	WindowsBuildChecker() = delete;

	std::unordered_map <std::string, WindowsBuilds> Builds;

	WindowsBuildChecker()
	{
		Builds["10240"] = b_10240;
		Builds["10586"] = b_10586;	
		Builds["14393"] = b_14393;	
		Builds["15063"] = b_15063;
		Builds["16299"] = b_16299;	
		Builds["17134"] = b_17134;	
		Builds["17763"] = b_17763;	
		Builds["18362"] = b_18362;	
		Builds["18363"] = b_18363;	
		Builds["19041"] = b_19041;
		Builds["19042"] = b_19042;	
		Builds["19043"] = b_19043;
		Builds["19044"] = b_19044;
		Builds["19045"] = b_19045;
		Builds["21996"] = b_21996;
		Builds["22000"] = b_22000;
		Builds["22621"] = b_22621;
		Builds["22631"] = b_22631;
		Builds["26100"] = b_26100;
	}

	WindowsVersion GetWindowsVersion()
	{
		RTL_OSVERSIONINFOW osVersionInfo;
		osVersionInfo.dwOSVersionInfoSize = sizeof(osVersionInfo);

		NTSTATUS status = RtlGetVersion(&osVersionInfo);

		if (status != 0)
		{
#if USE_LOG_MESSAGES
			Logger::logf(Warning, "Services::GetWindowsMajorVersion failed with error: %x");
#endif
			return ErrorUnknown;
		}

		if (osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 0)
		{
			return Windows2000;
		}
		else if (osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 1)
		{
			return WindowsXP;
		}
		else if (osVersionInfo.dwMajorVersion == 5 && osVersionInfo.dwMinorVersion == 2)
		{
			return WindowsXPProfessionalx64;
		}
		else if (osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 0)
		{
			return WindowsVista;
		}
		else if (osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 1) //0x0601
		{
			return Windows7;
		}
		else if (osVersionInfo.dwMajorVersion == 6 && osVersionInfo.dwMinorVersion == 2)
		{
			return Windows8;
		}
		else if (osVersionInfo.dwMajorVersion == 10 && osVersionInfo.dwMinorVersion == 0) //0x0A00
		{
			if (osVersionInfo.dwBuildNumber < 21996)
			{
				return Windows10;
			}
			else
			{
				return Windows11;
			}
		}

		return ErrorUnknown;
	}


	WindowsBuilds GetBuildNumber()
	{
		WindowsBuilds build = WindowsBuilds::b_Unknown;
		HKEY hKey = 0;
		const char* subKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			char buildNumber[256];
			DWORD bufferSize = sizeof(buildNumber);
			if (RegQueryValueExA(hKey, "CurrentBuildNumber", nullptr, nullptr, (LPBYTE)buildNumber, &bufferSize) == ERROR_SUCCESS)
			{
				std::string strBuild = buildNumber;

				if (strBuild.empty())
				{
					RegCloseKey(hKey);
					return WindowsBuilds::b_Unknown;
				}
					
#if USE_LOG_MESSAGES
				Logger::logf(Info, "Windows Build Number: %s", buildNumber);
#endif
				build = this->Builds[strBuild];
			}
			else
			{
#if USE_LOG_MESSAGES
				Logger::logf(Err, "Failed to read build number: %d @ GetBuildNumber", GetLastError());
#endif
				build = b_Unknown;
			}

			RegCloseKey(hKey);
		}
		else
		{
#if USE_LOG_MESSAGES
			Logger::logf(Err, "Failed to open registry key: %d @ GetBuildNumber", GetLastError());
#endif
			build = b_Unknown;
		}

		return build;
	}

};