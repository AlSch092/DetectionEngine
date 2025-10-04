# DetectionEngine
<img width="1355" height="475" alt="image" src="https://github.com/user-attachments/assets/44b2aaea-be45-49e5-9185-3b05b6ed062e" />
 
## What is this?
A generic detection engine implemented as a static library in C++ 14 (.lib) for Windows, which uses downloadable custom rulesets to detect and block processes. Can be used in anti-virus, anti-cheat, anti-crypto mining, etc. The code has been tested for memory & resource leaks, and can run successfully as a Windows Service for multiple weeks at a time. It uses as little CPU as possible, and most often never goes above 3% usage (tested on an Intel 6700K). WoW64 and 32-bit build are supported for most, if not all detections.    

The program makes use of inheritance, where a Detection base (`IDetector`) is derived from to create each specific detection. Settings for each detection are created in a .JSON file which is grabbed over HTTP at runtime, allowing you to add new detection fragments without re-compiling the program (for example, you can add or remove blacklisted CRC32's on the server-side). The library can be combined with other libraries, such as [UltimateDRM](https://github.com/AlSch092/UltimateDRM/) (in this case, using both DetectionEngine and UDRM will give you a crude anti-cheat/anti-virus program). 

## Included Detections
- `ByteSignatureScan.hpp` -> Byte pattern in process `.text`   
- `CommandLineScan.hpp`  -> Command line of process  
- `CoreIsolationScan.hpp`  -> Check if HVCI is enabled  
- `DriverSignatureEnforcementScan.hpp` -> Check if DSE/Test mode is enabled  
- `FileHashScanner.hpp` -> Check CRC32 of files & processes  
- `HypervisorScan.hpp` -> Check if system running under hypervisor  
- `IATScan.hpp` -> Check if IAT is modified  
- `LoadedDriverScan.hpp` -> Search for specific loaded drivers  
- `ManualMapScan.hpp` -> Check for manually mapped regions  
- `NetworkScan.hpp` -> Check for specific network connections  
- `ProcessElevatedScan.hpp`  -> Check if current process running as admin  
- `ProcessHandlesScan.hpp` -> Find open process handles to specific process  
- `ProcessScan.hpp` -> List running processes  
- `ProcessStringScanner.hpp` -> Search .rdata of processes for specific strings  
- `ResourceUsageScan.hpp` -> Check GPU & CPU usage, flag process above certain % usage    
- `SecureBootScan.hpp`  -> Check if secure boot is enabled  
- `UnsignedLoadedModulesScan.hpp`  -> Check for unsigned loaded modules    

Custom detections can also be added using the library's `DetectionManager` class. An example of a JSON ruleset file can be found as `Rules.json`.

## Features  
- Callbacks on process creation & exits  
- Callbacks on DLL loads & unloads  
- Authenticode/cert checks on loaded modules  
- Telemetry system for pushing events & flagged processes to a server over HTTP  
- Uses rule sets which can be customized based on your use case, with optional encrypting (Twofish) in-transit of the rules data  
- Supports both 64-bit and 32-bit processes, and WoW64  
- Most static strings are encrypted at compile time and decrypted on the stack at runtime when needed  
- Each scan/detection can be customized, with a variety of scan types (process scan, non-process scan, system config scan, self-scan, fixed process ID scan, one-time scan, etc)  
- Scans run at intervals based on their scan type: process scans run when a new process is created, one-time scans run once at startup, non-process scans run every X seconds  
- Scan settings include option for terminating flagged processes   
- Suitable to be run as a Windows Background Service, no found resource leaks  

## Dependencies  
This project makes use of the Capstone library. you will need to have `lib/capstone.lib` and/or `lib/capstone-d.lib` (debug build version). It also uses `HttpLib` which is a basic cURL wrapper that I made, and is part of the project solution (`lib/HttpLib.lib`, `lib/HttpLib32.lib` (32-bit), and `lib/HttpLib-d.lib`, `lib/HttpLib32-d.lib` for debug build). You can either use the libs provided in the `lib` folder or compile them yourself and put them in that folder.  

## Licensing
The project uses GNU GENERAL PUBLIC LICENSE VERSION 3  


