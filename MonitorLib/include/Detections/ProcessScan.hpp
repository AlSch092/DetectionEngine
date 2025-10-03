// Made by AlSch092 @ GitHub
#pragma once
#include "../IDetector.hpp"
#include "../ProcessHelper.hpp"
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <mutex>

class ProcessScan : public IDetector //simple process enumerator
{
private:
	std::vector<PROCESS_DATA> ProcessList;
	std::mutex ProcessListMutex;

public:
	ProcessScan() = default;
	~ProcessScan() = default;

	ProcessScan(__in const DetectionRule& rule)
	{
		this->Deserialize(rule);
	}

	std::vector<PROCESS_DATA> GetProcessList()
	{
		std::lock_guard<std::mutex> lock(ProcessListMutex);
		return ProcessList;
	}

	void AddProcess(const PROCESS_DATA& p)
	{
		std::lock_guard<std::mutex> lock(ProcessListMutex);
		if (std::find(ProcessList.begin(), ProcessList.end(), p) == ProcessList.end())
			ProcessList.push_back(p);
	}

	static std::vector<PROCESS_DATA> GetProcesses()
	{
		std::vector<PROCESS_DATA> ProcessList;

		DWORD dwProcs[1024], cbNeeded = 0, nProcesses = 0;

		if (!K32EnumProcesses(dwProcs, sizeof(dwProcs), &cbNeeded))
		{
			return {};
		}

		nProcesses = cbNeeded / sizeof(DWORD);

		for (int i = 0; i < nProcesses; i++)
		{
			if (dwProcs[i] != 0)
			{
				PROCESS_DATA p;
				p.pid = dwProcs[i];
				p.path = ProcessHelper::GetProcessPathByPID(dwProcs[i]);
				ProcessList.push_back(p);
			}
		}

		return ProcessList;
	}

	DetectionResult Run() override
	{
		if (!this->Enabled())
			return {};

		DetectionResult result;
		result.Flag = DetectionFlags::NONE;
		this->RunCount++;

		{
			std::lock_guard<std::mutex> lock(ProcessListMutex);
			ProcessList.clear();
		}

		DWORD dwProcs[1024], cbNeeded = 0, nProcesses = 0;

		if (!K32EnumProcesses(dwProcs, sizeof(dwProcs), &cbNeeded))
		{
			result.Flag = DetectionFlags::EXECUTION_ERROR;
			return result;
		}

		nProcesses = cbNeeded / sizeof(DWORD);

		for (int i = 0; i < nProcesses; i++)
		{
			if (dwProcs[i] != 0)
			{
				PROCESS_DATA p;
				p.pid = dwProcs[i];
				p.path = ProcessHelper::GetProcessPathByPID(dwProcs[i]);
				AddProcess(p);
			}
		}

		return result;
	}
};