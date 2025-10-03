// Made by AlSch092 @ GitHub
#pragma once
#include <iostream>
#include <fstream>
#include <cstdint>

/*
    CRC32 crc32;

    // Calculate CRC32 for the file
    uint32_t result = crc32.calculate(filePath);
    std::cout << "CRC32: " << std::hex << result << std::endl;
*/

class _CRC32 final
{
public:
    _CRC32()
    {
        // Initialize the CRC32 table
        for (uint32_t i = 0; i < 256; ++i)
        {
            uint32_t crc = i;
            for (uint32_t j = 8; j > 0; --j)
            {
                if (crc & 1)
                {
                    crc = (crc >> 1) ^ 0xEDB88320;
                }
                else
                {
                    crc = crc >> 1;
                }
            }
            table[i] = crc;
        }
    }

    uint32_t calculate(const std::string& filePath)
    {
        uint32_t crc = 0xFFFFFFFF; // Initial CRC value

        // Open the file
        std::ifstream file(filePath, std::ios::binary);
        if (!file)
        {
            std::cout << "Error opening file: " << filePath << std::endl;
            return 0;
        }

        // Read file in chunks
        char buffer[4096]; // 4 KB buffer
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
        {
            for (std::streamsize i = 0; i < file.gcount(); ++i)
            {
                uint8_t byte = buffer[i];
                crc = (crc >> 8) ^ table[(crc & 0xFF) ^ byte];
            }
        }

        // Finalize the CRC
        file.close();
        return crc ^ 0xFFFFFFFF;
    }

private:
    uint32_t table[256]{ 0 }; // CRC32 lookup table
};