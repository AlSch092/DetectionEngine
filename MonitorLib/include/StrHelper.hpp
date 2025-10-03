//By Alsch092 @ Github
#pragma once
#include <string>
#include <algorithm>
#include <cwctype> //std::towlower

/**
* @brief StrHelper class provides static methods to help with string operations
*/
class StrHelper final
{
public:
    static bool strcmp_insensitive(__in const std::string& a, __in const std::string& b)
    {
        std::string lowerStr_a = a;
        std::string lowerStr_b = b;

        std::transform(lowerStr_a.begin(), lowerStr_a.end(), lowerStr_a.begin(), [](char ch) { return std::towlower(ch); });
        std::transform(lowerStr_b.begin(), lowerStr_b.end(), lowerStr_b.begin(), [](char ch) { return std::towlower(ch); });

        return (lowerStr_a == lowerStr_b);
    }

    static bool wstrcmp_insensitive(__in const std::wstring& a, __in const std::wstring& b)
    {
        std::wstring lowerStr_a = a;
        std::wstring lowerStr_b = b;

        std::transform(lowerStr_a.begin(), lowerStr_a.end(), lowerStr_a.begin(), [](wchar_t ch) { return std::towlower(ch); });
        std::transform(lowerStr_b.begin(), lowerStr_b.end(), lowerStr_b.begin(), [](wchar_t ch) { return std::towlower(ch); });

        return (lowerStr_a == lowerStr_b);
    }

    static bool ContainsStr(__in const std::string& needle, __in const std::string& haystack)
    {
        std::string needle_low = ToLower(needle);
        std::string haystack_low = ToLower(haystack);

        return (haystack_low.find(needle_low) != std::string::npos);
    }

    static bool ContainsStrW(__in const std::wstring& needle, __in const std::wstring& haystack)
    {
        std::wstring needle_low = ToLower(needle);
        std::wstring haystack_low = ToLower(haystack);

        return (haystack_low.find(needle_low) != std::wstring::npos);
    }

    static std::string ToLower(__in const std::string& str)
    {
        std::string lower = str;
        std::transform(str.begin(), str.end(), lower.begin(), [](__in const char c) { return std::tolower(c); });
        return lower;
    }

    static std::wstring ToLower(__in const std::wstring& str)
    {
        std::wstring lower = str;
        std::transform(str.begin(), str.end(), lower.begin(), [](__in const wchar_t c) { return std::tolower(c); });
        return lower;
    }

    static std::string WStringToString(const std::wstring& wstr)
    {
        if (wstr.empty())
            return {};

        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);

        std::string result(sizeNeeded, 0);

        WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &result[0], sizeNeeded, nullptr, nullptr);
        return result;
    }

    static std::wstring StringToWString(const std::string& str)
    {
        if (str.empty())
            return {};

        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
        std::wstring result(sizeNeeded, 0);

        MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &result[0], sizeNeeded);

        return result;
    }

    static bool HasExtension(__in const std::string& fileName, __in const std::string& extension)
    {
        std::string::size_type pos = fileName.rfind(extension);
        return (pos != std::string::npos) && (pos == fileName.length() - extension.length());
    }

    static bool HasExtension(__in const std::wstring& fileName, __in const std::wstring& extension)
    {
        std::wstring::size_type pos = fileName.rfind(extension);
        return (pos != std::wstring::npos) && (pos == fileName.length() - extension.length());
    }

    static std::vector<uint8_t> HexStringToBytes(const std::string& input)
    {
        std::vector<uint8_t> bytes;
        std::stringstream ss(input);
        std::string token;

        while (std::getline(ss, token, ','))
        {
            token.erase(0, token.find_first_not_of(" \t\n\r"));
            token.erase(token.find_last_not_of(" \t\n\r") + 1);

            if (token.rfind("0x", 0) == 0 || token.rfind("0X", 0) == 0)
            {
                token = token.substr(2); // strip "0x"

                uint32_t value = 0;
                std::stringstream hexstream;
                hexstream << std::hex << token;
                hexstream >> value;

                bytes.push_back(static_cast<uint8_t>(value & 0xFF));
            }
            else if (token.rfind("?", 0) == 0) //wildcard byte
            {
                bytes.push_back(static_cast<uint8_t>('?'));
            }
        }

        return bytes;
    }

};