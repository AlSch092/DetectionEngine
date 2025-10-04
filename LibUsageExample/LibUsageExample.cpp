// LibUsageExample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include "../MonitorLib/include/DetectionManager.hpp"

#pragma comment(lib, "../x64/Release/DetectionLib.lib")
#pragma comment(lib, "../MonitorLib/lib/brotlidec.lib")
#pragma comment(lib, "../MonitorLib/lib/brotlicommon.lib")
#pragma comment(lib, "ws2_32.lib")

int main()
{
    std::cout << "Creating Detection Manager...\n";

    std::unique_ptr<DetectionManager> dm = nullptr;

    try
    {
        dm = std::make_unique<DetectionManager>(true, "http://localhost:5002/v1/PushTelemetry", true, true, true); //using telemetry, monitor proc creation, dll notifs, and unsigned module checking
        //dm = std::make_unique<DetectionManager>(false, "", true, true, true); //if not using telemetry.. uncomment this line, comment above line
    }
    catch (const std::bad_alloc& ex)
    {
        std::cerr << "Failed to allocate detection manager smart ptr: " << ex.what() <<  std::endl;
		return -1;
    }

    const std::string repoUrl = "http://localhost:5000/Rules.json"; //url to your rules server

    if (!dm->FetchDetectionRules(repoUrl, false)) //if bEncrypt = true, your rules.json file on the server-side must be encrypted using Twofish CBC with the key and IV defined in TwoFishCryptMgr.hpp
    {
        std::cerr << "Failed to fetch detection rules!" << std::endl;
        return -1;
    }

    if (!dm->StartDetections())
    {
        std::cerr << "Failed to start detections!" << std::endl;
        return -1;
    }
    
    std::cout << "Enter 'q' or 'Q' to quit the program...\n";

    char ch = 0;

    while (ch != 'q' && ch != 'Q')
    {
        std::cin >> ch;
    }

    dm->ScheduleShutdown(true);

    return 0;
}

