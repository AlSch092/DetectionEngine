// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include <Windows.h>
#include <mutex>

struct Driver
{
	std::wstring baseName;
	std::wstring path;
	uint32_t FileHash = 0; //crc32
	bool bIsSigned = false;

	bool operator== (const Driver& other) const noexcept
	{
		return (baseName == other.baseName && path == other.path);
	}
};

/**
* @brief The LoadedDriverScan class checks for specific loaded drivers, either by name of by their disc file's CRC32 value.
* This class is not yet implemented.
*
*/
class LoadedDriverScan : public IDetector //one-shot check
{
private:
	std::vector<Driver> LoadedDriverList;
	std::mutex DriverListMutex;

	std::vector<Driver> GetLoadedDrivers()
	{
		std::vector<Driver> driverList;
		return driverList;
	}

public:
	LoadedDriverScan() = default;
	~LoadedDriverScan() = default;

	LoadedDriverScan(__in const DetectionRule& rule)
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

		
		return result;
	}
};