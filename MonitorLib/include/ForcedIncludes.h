//By Alsch092 @ Github
// Forced includes to resolve common issues with Windows.h and Winsock2.h
//#ifndef WIN32_LEAN_AND_MEAN
//#define WIN32_LEAN_AND_MEAN
//#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Ensure Winsock2 is chosen and comes BEFORE Windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
