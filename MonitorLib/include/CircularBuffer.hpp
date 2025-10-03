// Made by AlSch092 @ GitHub
#pragma once

#include <atomic>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <fstream>

template <typename T, std::size_t N>
class CircularBuffer
{
private:
    static_assert((N& (N - 1)) == 0, "N must be power of 2");
    static constexpr size_t capacity = N;
    static constexpr size_t Mask = N - 1;

    std::aligned_storage_t<sizeof(T), alignof(T)> storage[N];

    alignas(64) std::atomic<size_t> ReadIndex{ 0 }; //head
    char _pad1[64 - sizeof(ReadIndex)]{};
    alignas(64) std::atomic<size_t> WriteIndex{ 0 }; //tail
    char _pad2[64 - sizeof(WriteIndex)]{};

public:

    bool Head(T& out)
    {
        size_t Writeindx = WriteIndex.load(std::memory_order_acquire);
        size_t Readindx = ReadIndex.load(std::memory_order_relaxed);
        if (Readindx == Writeindx)
            return false;

        //T* p = std::launder(reinterpret_cast<const T*>(&storage[Readindx & Mask]));
        //out = *p;
        out = reinterpret_cast<T&>(storage[Readindx & Mask]);
        return true;
    }

    bool Tail(T& out)
    {
        size_t Writeindx = WriteIndex.load(std::memory_order_acquire);
        size_t Readindx = ReadIndex.load(std::memory_order_relaxed);
        if (Readindx == Writeindx)
            return false;

        //T* p = std::launder(reinterpret_cast<const T*>(&storage[Writeindx & Mask]));
        //out = *p;
        out = reinterpret_cast<T&>(storage[Writeindx & Mask]);
        return true;
    }

    bool TryPush(T&& val) //put onto tail (producer)
    {
        size_t Writeindx = WriteIndex.load(std::memory_order_relaxed);
        size_t ReadIndx = ReadIndex.load(std::memory_order_acquire);

        if (Writeindx - ReadIndx >= capacity) //full
        {
            return false;
        }

        ::new(&storage[Writeindx & Mask]) T(std::move(val));
        WriteIndex.store(Writeindx + 1, std::memory_order_release); //publish
        return true;
    }

    bool TryPop(T& val) //take from head (consumer)
    {
        size_t ReadIndx = ReadIndex.load(std::memory_order_relaxed);
        size_t Writeindx = WriteIndex.load(std::memory_order_acquire);

        if (ReadIndx == Writeindx) //empty
        {
            return false;
        }

        //auto p = std::launder(reinterpret_cast<T*>(&storage[ReadIndx & Mask]));
        //val = std::move(*p);
        //p->~T();
        val = reinterpret_cast<T&>(storage[ReadIndx & Mask]);
        reinterpret_cast<T*>(&storage[ReadIndx & Mask]) -> ~T();
        ReadIndex.store(ReadIndx + 1, std::memory_order_release); //publish
        return true;
    }

    bool Empty() const
    {
        return (ReadIndex.load(std::memory_order_acquire) == WriteIndex.load(std::memory_order_acquire));
    }

    bool Full() const
    {
        return (WriteIndex.load(std::memory_order_acquire) - ReadIndex.load(std::memory_order_acquire) >= capacity);
    }
};


template<typename T, size_t N>
class MPSC
{
private:

    std::mutex ChannelMutex;
    std::unordered_map<std::thread::id, std::unique_ptr<CircularBuffer<T, N>>> Channels;

    std::stringstream ss;
    std::ofstream ofs;

public:

    CircularBuffer<T, N>* GetChannel()
    {
        std::lock_guard<std::mutex> lock(ChannelMutex);

        auto& channel = Channels[std::this_thread::get_id()];

        if (channel == nullptr)
            channel = std::make_unique<CircularBuffer<T, N>>();

        return channel.get();
    }

    bool DrainVals(__in const std::string& fileName)
    {
        if (fileName.empty())
            return false;

        this->ofs = std::ofstream(fileName);

        std::unique_lock<std::mutex> lock(ChannelMutex);

        for (auto& channel : Channels)
        {
            while (!channel.second->Empty())
            {
                T val;
                channel.second->TryPop(val);

                ss << val.EventId << std::endl;
            }
        }

        ofs << ss.str();
        ofs.close();
        return true;
    }

    //JSON batch send, online endpoint
    bool DrainVals(__in const std::string& endpoint, __in const bool bEncrypt)
    {
        if (endpoint.empty())
            return false;

        if (bEncrypt)
        {

        }

        return true;
    }

};