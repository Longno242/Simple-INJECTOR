#include "InjectionCommon.h"

#include <tlhelp32.h>
#include <vector>

HANDLE OpenTargetProcess(DWORD pid, DWORD access) {
    return OpenProcess(access, FALSE, pid);
}

uintptr_t GetRemoteModuleBase(DWORD pid, const char* moduleName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me{ sizeof(MODULEENTRY32) };
    uintptr_t base = 0;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, moduleName) == 0) {
                base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

LPVOID RemoteAllocAnsiPath(HANDLE hProc, const std::string& path) {
    SIZE_T size = path.size() + 1;
    LPVOID alloc = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) return nullptr;
    if (!WriteProcessMemory(hProc, alloc, path.c_str(), size, nullptr)) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        return nullptr;
    }
    return alloc;
}

LPVOID RemoteAllocWidePath(HANDLE hProc, const std::string& path) {
    int wcharCount = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wcharCount <= 0) return nullptr;
    SIZE_T byteSize = static_cast<SIZE_T>(wcharCount) * sizeof(wchar_t);
    LPVOID alloc = VirtualAllocEx(hProc, nullptr, byteSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) return nullptr;
    std::vector<wchar_t> wide(static_cast<size_t>(wcharCount));
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wide.data(), wcharCount);
    if (!WriteProcessMemory(hProc, alloc, wide.data(), byteSize, nullptr)) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        return nullptr;
    }
    return alloc;
}

bool RemoteLoadLibraryA(HANDLE hProc, const std::string& dllName) {
    LPVOID alloc = RemoteAllocAnsiPath(hProc, dllName);
    if (!alloc) return false;
    auto pLoadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLib, alloc, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
    return exitCode != 0;
}

static std::string GetDllFileName(const std::string& path) {
    const size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

bool IsModuleLoaded(DWORD pid, const std::string& dllPath) {
    std::string name = GetDllFileName(dllPath);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32 me{ sizeof(MODULEENTRY32) };
    bool found = false;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, name.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

bool WaitForModuleLoad(DWORD pid, const std::string& dllPath, DWORD timeoutMs) {
    DWORD elapsed = 0;
    while (elapsed < timeoutMs) {
        if (IsModuleLoaded(pid, dllPath)) return true;
        Sleep(100);
        elapsed += 100;
    }
    return false;
}

bool FinishLoadLibraryThread(HANDLE hProc, LPVOID alloc, HANDLE hThread) {
    bool ok = false;
    if (hThread) {
        WaitForSingleObject(hThread, 8000);
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        ok = exitCode != 0;
        CloseHandle(hThread);
    }
    if (alloc) VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return ok;
}
