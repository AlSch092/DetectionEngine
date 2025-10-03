//By Alsch092 @ Github
#pragma once

template<typename T>
class SetOnce
{
public:
    SetOnce(T init) : m_Val(init)
    {}

    SetOnce<T>& operator=(const T& other)
    {
        std::call_once(m_OnceFlag, [&]()
        {
            m_Val = other;
        });

        return *this;
    }

    const T& get() { return m_Val; }
private:
    T m_Val;
    std::once_flag m_OnceFlag;
};