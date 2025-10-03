// DetectionResult.hpp
#pragma once
#include <string>
#include <chrono>
#include <unordered_map>

enum class DetectionSeverity { Info, Warning, Critical };

enum DetectionFlags
{
	NONE = 0,
	UNKNOWN = 1,
	EXECUTION_ERROR = 2,

	PAGE_PROTECTIONS = 1000,
	CODE_INTEGRITY,   //.text section changes
	GAME_PROCESS_CODE_INTEGRITY,
	DLL_TAMPERING, //hooking or modifying loaded DLLs
	BAD_IAT, //IAT hooking
	OPEN_PROCESS_HANDLES,
	UNSIGNED_DRIVERS, //test signing mode
	LOADED_UNSIGNED_MODULE, //injected to current process
	LOADED_GAME_UNSIGNED_MODULE,
	INJECTED_ILLEGAL_PROGRAM,
	EXTERNAL_ILLEGAL_PROGRAM,
	MANUAL_MAPPED_MEMORY,
	FLAGGED_DRIVER,
	FLAGGED_EXE,
	SECURE_BOOT_DISABLED,
	PROCESS_NOT_ADMIN,
	PYTHON_SCRIPT,
	PACKAGED_PYTHON_EXE,
	BLACKLISTED_WINDOW_TEXT,
	BLACKLISTED_BYTE_PATTERN,
	BLACKLISTED_FILE_CRC32,
	BLACKLISTED_DATA_STRING,
	BLACKLISTED_COMMAND_LINE,
	BLACKLISTED_NETWORK_CONNECTION,
	FLAGGED_HARDWARE, //any DMA-related hardware
	THREAD_SUSPENDED,
	HYPERVISOR,
	HVCI_DISABLED,
	REGISTRY_KEY_MODIFICATIONS,
	TEST_SIGNING_MODE,
	DEBUG_MODE,
	WINDOWS_VERSION_BELOW_10,
	VULNERABLE_DRIVER_LIST_DISABLED,
	WMI_NOT_STARTABLE,
	WMI_DISABLED,
	HIGH_GPU_USAGE,
	HIGH_CPU_USAGE,

	//DEBUGGER DETECTIONS ----------------
	DEBUG_WINAPI_DEBUGGER = 10000,
	DEBUG_PEB,
	DEBUG_HARDWARE_REGISTERS,
	DEBUG_HEAP_FLAG,
	DEBUG_INT3,
	DEBUG_INT2C,
	DEBUG_INT2D,
	DEBUG_CLOSEHANDLE,
	DEBUG_DEBUG_OBJECT,
	DEBUG_VEH_DEBUGGER,
	DEBUG_KERNEL_DEBUGGER,
	DEBUG_TRAP_FLAG,
	DEBUG_DEBUG_PORT,
	DEBUG_PROCESS_DEBUG_FLAGS,
	DEBUG_REMOTE_DEBUGGER,
	DEBUG_DBK64_DRIVER,
	DEBUG_KNOWN_DEBUGGER_PROCESS
	///DEBUGGER DETECTIONS ----------------
};

struct DetectionResult 
{
	std::vector<uint32_t> AssociatedScanIds; //scanIds used to produce the result

    DetectionFlags Flag = DetectionFlags::NONE;
    std::string Description;
    uint32_t ProcessId = 0;
    uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

	bool operator==(const DetectionResult& other) const noexcept
	{
		return Flag == other.Flag && Description == other.Description;
	}

	DetectionResult() = default;

	DetectionResult(DetectionFlags f, std::string desc, uint32_t pid, DetectionSeverity sev)
		: Flag(f), Description(desc), ProcessId(pid)
	{
	}
};

