//By Alsch092 @ Github
#pragma once
#include <windows.h>

class HandleGuard  //RAII handle wrapper
{
    HANDLE h = INVALID_HANDLE_VALUE;
public:
    explicit HandleGuard(HANDLE h) : h(h) {}
    ~HandleGuard() { if (h != INVALID_HANDLE_VALUE && h != 0) CloseHandle(h); }

    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;

    // allow move
    HandleGuard(HandleGuard&& other) noexcept : h(other.h) 
    {
        other.h = INVALID_HANDLE_VALUE;
    }

    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            reset();
            h = other.h;
            other.h = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    bool isValid() const noexcept 
    {
        return h != nullptr && h != INVALID_HANDLE_VALUE && h != 0;
    }

    operator bool() const
    {
        return isValid();
    }

    operator HANDLE() const noexcept { return h; }
    HANDLE get() const noexcept { return h; }

    void reset(HANDLE newHandle = INVALID_HANDLE_VALUE) noexcept 
    {
        if (isValid())
            CloseHandle(h);
        h = newHandle;
    }

    HANDLE release() noexcept 
    {
        HANDLE tmp = h;
        h = INVALID_HANDLE_VALUE;
        return tmp;
    }
};