// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../CRC32.hpp"
#include "../ProcessHelper.hpp"
#include "../StrHelper.hpp"
#include <unordered_map>

/**
* @brief The FileHashScanner class checks the CRC32 of specific files on disc to find any blacklisted hash values.
*
*/
class FileHashScanner : public IDetector
{
private:
	std::unordered_map<uint32_t, bool> CRC32sDetected; //todo: clear this every hour or so to prevent excessive mem usage

	bool CheckDirectoryForFileHash(const std::wstring& directoryPath, const uint32_t knownHash)
	{
		WIN32_FIND_DATA findFileData;
		HANDLE hFind = FindFirstFile((directoryPath + L"\\*").c_str(), &findFileData);

		if (hFind == INVALID_HANDLE_VALUE)
		{
			std::wcerr << L"Failed to open directory: " << directoryPath << std::endl;
			return false;
		}

		do
		{
			if (findFileData.cFileName[0] == L'.') //skip "." and ".."
			{
				continue;
			}

			std::wstring fullPath = directoryPath + L"\\" + findFileData.cFileName; //build the full file path

			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) // Skip directories
			{
				continue;
			}

			if (!StrHelper::HasExtension(findFileData.cFileName, L".exe") && !StrHelper::HasExtension(findFileData.cFileName, L".dll")) //only check .exe files and .dll
			{
				continue;
			}

			_CRC32 crc;
			uint32_t hash = crc.calculate(StrHelper::WStringToString(fullPath));

			if (hash == knownHash)
			{
				FindClose(hFind);
				return true;
			}

		} while (FindNextFile(hFind, &findFileData));

		FindClose(hFind);
		return false;
	}

public:
	FileHashScanner() = default;
    ~FileHashScanner() = default;

	FileHashScanner(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);

		for (const auto& hash : rule.Artifacts)
		{
			if (!hash.empty())
				this->AddCrc32(strtoul(hash.c_str(), nullptr, 16));
		}
	}

	std::list<uint32_t> GetDetectedList() const 
	{ 
		std::list<uint32_t> DetectedList;

		for (const auto& crc32 : CRC32sDetected)
		{
			if (crc32.second)
				DetectedList.push_back(crc32.first);
		}

		return DetectedList;
	}

    void AddCrc32(const uint32_t crc32)
    {
		CRC32sDetected[crc32] = false;
    }

	DetectionResult Run(const std::wstring& modulePath) //for OnDllLoad
	{
		if (!this->Enabled())
			return {};

		DetectionResult result;
		result.Flag = DetectionFlags::NONE;

		this->RunCount++;

		if (modulePath.empty())
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		_CRC32 crc;
		uint32_t hash = crc.calculate(StrHelper::WStringToString(modulePath));

		if (hash == 0)
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		for (const auto& crc : CRC32sDetected)
		{
			if (hash == crc.first)
			{
				result.Flag = DetectionFlags::BLACKLISTED_FILE_CRC32;
				result.Description = StrHelper::WStringToString(modulePath);
				result.ProcessId = GetCurrentProcessId();
				CRC32sDetected[hash] = true;
			}
		}

		return result;
	}

    DetectionResult Run() override
    {
        DetectionResult result;

		bool bFoundBlacklistedCrc = false;
		uint32_t blacklistedCrc = 0;

        std::wstring filePath = ProcessHelper::GetProcessPathByPID(this->ProcessId);

		if (filePath.empty())
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

        if (filePath[0] == L'[') //skip any system process -> Starts in [System]
            return result;

		_CRC32 crc;
        uint32_t hash = crc.calculate(StrHelper::WStringToString(filePath));

        if (hash == 0 && filePath != L"Error: Path not available") //file on disc not found for ProcessId, may imply file renaming (evasion)
        {
            std::wstring directory = filePath.substr(0, filePath.find_last_of(L"\\"));

			for (const auto& crc : CRC32sDetected)
			{
				if (CheckDirectoryForFileHash(directory, crc.first))
				{
					blacklistedCrc = crc.first;
					bFoundBlacklistedCrc = true;
					break;
				}
			}
        }
        else
        {
            for (const auto& crc : CRC32sDetected)
            {
                if (hash == crc.first)
                {
					blacklistedCrc = crc.first;
					bFoundBlacklistedCrc = true;
					break;
                }
            }
        }

		if (bFoundBlacklistedCrc)
		{
			result.Flag = DetectionFlags::BLACKLISTED_FILE_CRC32;
			result.Description = std::to_string(blacklistedCrc);
			result.ProcessId = this->ProcessId;

			CRC32sDetected[blacklistedCrc] = true;
		}

        return result;
    }
};