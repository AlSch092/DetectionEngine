//By Alsch092 @ Github
#pragma once
#include <WbemCli.h>
#include <comutil.h>
#include <combaseapi.h>
#include <wrl/client.h>
#include <iostream>

#pragma comment(lib, "wbemuuid.lib")

#ifdef _DEBUG
#pragma comment(lib, "comsuppwd.lib")
#else
#pragma comment(lib, "comsuppw.lib")
#endif

using Microsoft::WRL::ComPtr;

class ComMTA 
{
    bool needUninit = false;
public:
    HRESULT ensure() 
    {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        if (hr == S_OK) 
        { 
            needUninit = true;  
            return S_OK; 
        }
        if (hr == S_FALSE) 
        { 
            needUninit = false; 
            return S_OK; 
        }

        if (hr == RPC_E_CHANGED_MODE) 
            return hr; 

        return hr;
    }
    ~ComMTA() { if (needUninit) CoUninitialize(); }
};

inline HRESULT EnsureComOnThisThread()
{
    thread_local ComMTA g;
    static thread_local bool inited = false;
    static thread_local HRESULT last = E_UNEXPECTED;

    if (!inited) 
    { 
        last = g.ensure(); 
        inited = true; 
    }

    return last;
}

class WMI
{
public:
     bool InitializeCOM();
     HRESULT  ConnectToWMI(ComPtr<IWbemServices>& svc);
	 bool IsWMIServiceRunning();
	 bool StartWMIService();

	 bool bInitializedCOM = false;

     void SetwmiInterface(ComPtr<IWbemServices> wmii) { this->wmiInterface = wmii; }

     IWbemServices* GetWMIInterface() const { return this->wmiInterface.Get(); }

private:
    ComPtr<IWbemServices> wmiInterface = nullptr;
};