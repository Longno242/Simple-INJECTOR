#pragma once

#include <windows.h>
#include <string>

constexpr DWORD kAccessQueryVm = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
    PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
constexpr DWORD kAccessInjectThread = kAccessQueryVm | PROCESS_CREATE_THREAD;

HANDLE OpenTargetProcess(DWORD pid, DWORD access);
uintptr_t GetRemoteModuleBase(DWORD pid, const char* moduleName);
LPVOID RemoteAllocAnsiPath(HANDLE hProc, const std::string& path);
LPVOID RemoteAllocWidePath(HANDLE hProc, const std::string& path);
bool RemoteLoadLibraryA(HANDLE hProc, const std::string& dllName);
bool IsModuleLoaded(DWORD pid, const std::string& dllPath);
bool WaitForModuleLoad(DWORD pid, const std::string& dllPath, DWORD timeoutMs = 8000);
bool FinishLoadLibraryThread(HANDLE hProc, LPVOID alloc, HANDLE hThread);
