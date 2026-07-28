#pragma once

#include <windows.h>
#include <string>

bool InjectDLL(DWORD pid, const std::string& dllPath, int method, bool eraseHeaders);
bool InjectLoadLibrary(DWORD pid, const std::string& dllPath);
bool InjectLoadLibraryW(DWORD pid, const std::string& dllPath);
bool InjectNtCreateThreadEx(DWORD pid, const std::string& dllPath);
bool InjectRtlCreateUserThread(DWORD pid, const std::string& dllPath);
bool InjectQueueUserAPC(DWORD pid, const std::string& dllPath);
bool InjectThreadHijack(DWORD pid, const std::string& dllPath);
bool ManualMap(DWORD pid, const std::string& dllPath, bool eraseHeaders);
