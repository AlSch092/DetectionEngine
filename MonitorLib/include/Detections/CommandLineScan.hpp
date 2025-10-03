// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../StrHelper.hpp"
#include "../WMI.hpp"
#include <mutex>

#ifdef _WIN32
#include "../ProcessHelper.hpp"
#else
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#endif

/**
* @brief The CommandLineScan checks the command line of a specific process ID for any blacklisted substrings.
* 
*/
class CommandLineScan final : public IDetector
{
private:
	std::list<std::string> ProcessNames; //optional list of specific processes to check only for `FlaggedCommandLines`
	std::list<std::string> FlaggedCommandLines;

	bool bFoundFlaggedCmdLine = false;

	std::mutex ListMutex;

public:

	CommandLineScan() = default;
	~CommandLineScan() = default;

	CommandLineScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);

		for (const auto& str : rule.Artifacts) //add blacklisted strings
		{
			std::string str_lower = StrHelper::ToLower(str);
			this->AddFlaggedCommandLine(str_lower);
		}
	}

	void AddFlaggedCommandLine(__in const std::string& cmdLine)
	{
		std::lock_guard<std::mutex> lock(ListMutex);

		if (!cmdLine.empty())
			if (std::find(FlaggedCommandLines.begin(), FlaggedCommandLines.end(), cmdLine) == FlaggedCommandLines.end())
				FlaggedCommandLines.push_back(cmdLine);
	}

	DetectionResult Run() override
	{
		if (FAILED(EnsureComOnThisThread()))
		{
#ifdef _LOGGING_ENABLED
			printf("EnsureComOnThisThread FAILED @ CommandLineScan::Run\n");
#endif
			return {};
		}


		if (!this->Enabled())
			return {};

		DetectionResult result;
		result.Flag = DetectionFlags::NONE;
		this->RunCount++;

		std::wstring haystackW;
        ProcessHelper::GetProcessCommandLine(this->ProcessId, haystackW); //gets full cmd line, including path of program.  procParams.CommandLine.Buffer = UNICODE_STRING

		std::string haystack = StrHelper::WStringToString(haystackW);
		haystack = StrHelper::ToLower(haystack);

		if (haystack.empty())
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		{
			std::lock_guard<std::mutex> lock(ListMutex);

			for (const auto& needle : FlaggedCommandLines)
			{
				if (StrHelper::ContainsStr(needle, haystack))
				{
					result.Flag = DetectionFlags::BLACKLISTED_COMMAND_LINE;
					result.ProcessId = this->ProcessId;
					result.Description = StrHelper::WStringToString(ProcessHelper::GetProcessPathByPID(this->ProcessId)); //some cmd lines are very large and aren't suitable to store/send over network
					break;
				}
			}
		}
		
		return result;
	}
};