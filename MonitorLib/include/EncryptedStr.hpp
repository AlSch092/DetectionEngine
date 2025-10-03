//By Alsch092 @ Github
#pragma once
#include <cstddef>

namespace XorStr
{
    constexpr const char* XOR_KEY = "AlSch092";
	constexpr const int XOR_KEY_LEN = 7; //subtract 1 from actual length to make loop checks more 0-index friendly

    constexpr char encrypt_char(char c, char key, int index)
    {
        return c ^ (key + index);
    }

    constexpr char decrypt_char(char c, char key, int index)
    {
        return c ^ (key + index);
    }

    constexpr char encrypt_wchar(wchar_t c, wchar_t key, int index)
    {
        return c ^ (key + index);
    }

    constexpr char decrypt_wchar(wchar_t c, wchar_t key, int index)
    {
        return c ^ (key + index);
    }

    //compile-time string obfuscation using template recursion
    template <std::size_t N>
    class EncryptedString
    {
    private:
        char encrypted[N];

    public:
        constexpr EncryptedString(const char(&str)[N]) : encrypted{}
        {
            int key_index = 0;

            for (std::size_t i = 0; i < N; ++i)
            {
                encrypted[i] = encrypt_char(str[i], XOR_KEY[key_index], i);

                if (key_index >= XOR_KEY_LEN)
                    key_index = 0;
            }
        }

        //runtime decryption
        void decrypt(char* output)
        {
            int key_index = 0;

            for (std::size_t i = 0; i < N; ++i)
            {
                output[i] = decrypt_char(encrypted[i], XOR_KEY[key_index++], i);

                if(key_index >= XOR_KEY_LEN)
					key_index = 0;
            }
        }

        std::string decrypt() const
        {
            int key_index = 0;

            std::string s;
            s.reserve(N+1);
            for (std::size_t i = 0; i < N; ++i)
            {
                s.push_back(decrypt_char(encrypted[i], XOR_KEY[key_index++], i));

                if (key_index >= XOR_KEY_LEN)
                    key_index = 0;
            }

            return s;
        }

        constexpr int getSize() const { return N; }
    };

    template <std::size_t N>
    constexpr EncryptedString<N> make_encrypted(const char(&str)[N])
    {
        return EncryptedString<N>(str);
    }

    template <std::size_t N>
    class EncryptedStringW
    {
    private:
        wchar_t encrypted[N];

    public:

        constexpr EncryptedStringW(const wchar_t(&str)[N]) : encrypted{}
        {
            int key_index = 0;

            for (std::size_t i = 0; i < N; ++i)
            {
                encrypted[i] = encrypt_wchar(str[i], XOR_KEY[key_index++], i);

                if (key_index >= XOR_KEY_LEN)
                    key_index = 0;
            }
        }

        void decrypt(wchar_t* output)
        {
            int key_index = 0;

            for (std::size_t i = 0; i < N; ++i)
            {
                output[i] = decrypt_wchar(encrypted[i], XOR_KEY[key_index++], i);

                if (key_index >= XOR_KEY_LEN)
                    key_index = 0;
            }
        }

        std::wstring decrypt() const
        {
            int key_index = 0;

            std::wstring s;
            s.reserve(N + 1);
            for (std::size_t i = 0; i < N; ++i)
            {
                s.push_back(decrypt_char(encrypted[i], XOR_KEY[key_index++], i));

                if (key_index >= XOR_KEY_LEN)
                    key_index = 0;
            }

            return s;
        }

        constexpr int getSize() const { return N; }
    };

    template <std::size_t N>
    constexpr EncryptedStringW<N> make_encrypted(const wchar_t(&str)[N])
    {
        return EncryptedStringW<N>(str);
    }

}