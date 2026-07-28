#include "Injection.h"
#include "InjectionCommon.h"

#include <tlhelp32.h>
#include <winternl.h>

bool InjectLoadLibrary(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenTargetProcess(pid, kAccessInjectThread);
    if (!hProc) return false;

    SIZE_T size = dllPath.size() + 1;
    LPVOID alloc = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) { CloseHandle(hProc); return false; }

    if (!WriteProcessMemory(hProc, alloc, dllPath.c_str(), size, nullptr)) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    auto pLoadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLib, alloc, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(hThread, 8000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    if (exitCode != 0) return true;
    return WaitForModuleLoad(pid, dllPath);
}

bool InjectLoadLibraryW(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenTargetProcess(pid, kAccessInjectThread);
    if (!hProc) return false;

    LPVOID alloc = RemoteAllocWidePath(hProc, dllPath);
    if (!alloc) { CloseHandle(hProc); return false; }

    auto pLoadLibW = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLibW, alloc, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    return FinishLoadLibraryThread(hProc, alloc, hThread);
}

using fnNtCreateThreadEx = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

bool InjectNtCreateThreadEx(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenTargetProcess(pid, kAccessInjectThread);
    if (!hProc) return false;

    LPVOID alloc = RemoteAllocAnsiPath(hProc, dllPath);
    if (!alloc) { CloseHandle(hProc); return false; }

    auto pNtCreateThreadEx = reinterpret_cast<fnNtCreateThreadEx>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx"));
    if (!pNtCreateThreadEx) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    auto pLoadLib = reinterpret_cast<PVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
    HANDLE hThread = nullptr;
    NTSTATUS status = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hProc,
        pLoadLib, alloc, 0, 0, 0, 0, nullptr);

    if (status < 0 || !hThread) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    return FinishLoadLibraryThread(hProc, alloc, hThread);
}

using fnRtlCreateUserThread = NTSTATUS(NTAPI*)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PVOID, PVOID, PHANDLE, PVOID);

bool InjectRtlCreateUserThread(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenTargetProcess(pid, kAccessInjectThread);
    if (!hProc) return false;

    LPVOID alloc = RemoteAllocAnsiPath(hProc, dllPath);
    if (!alloc) { CloseHandle(hProc); return false; }

    auto pRtlCreateUserThread = reinterpret_cast<fnRtlCreateUserThread>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread"));
    if (!pRtlCreateUserThread) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    auto pLoadLib = reinterpret_cast<PVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
    HANDLE hThread = nullptr;
    NTSTATUS status = pRtlCreateUserThread(hProc, nullptr, FALSE, 0, 0, 0, pLoadLib, alloc, &hThread, nullptr);

    if (status < 0 || !hThread) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    return FinishLoadLibraryThread(hProc, alloc, hThread);
}

bool InjectQueueUserAPC(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenTargetProcess(pid, kAccessQueryVm);
    if (!hProc) return false;

    LPVOID alloc = RemoteAllocAnsiPath(hProc, dllPath);
    if (!alloc) { CloseHandle(hProc); return false; }

    auto pLoadLib = reinterpret_cast<PAPCFUNC>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    bool queued = false;
    THREADENTRY32 te{ sizeof(THREADENTRY32) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;
            if (QueueUserAPC(pLoadLib, hThread, reinterpret_cast<ULONG_PTR>(alloc)))
                queued = true;
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    if (!queued) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    bool ok = WaitForModuleLoad(pid, dllPath);
    VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return ok;
}

bool InjectThreadHijack(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenTargetProcess(pid, kAccessQueryVm);
    if (!hProc) return false;

    LPVOID alloc = RemoteAllocAnsiPath(hProc, dllPath);
    if (!alloc) { CloseHandle(hProc); return false; }

    auto pLoadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));

    DWORD targetTid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{ sizeof(THREADENTRY32) };
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    targetTid = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    if (!targetTid) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, targetTid);
    if (!hThread) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (SuspendThread(hThread) == static_cast<DWORD>(-1)) {
        CloseHandle(hThread);
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    bool ok = false;
    if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
        ctx.Rcx = reinterpret_cast<DWORD64>(alloc);
        ctx.Rip = reinterpret_cast<DWORD64>(pLoadLib);
#else
        ctx.Eax = reinterpret_cast<DWORD>(alloc);
        ctx.Eip = reinterpret_cast<DWORD>(pLoadLib);
#endif
        ok = SetThreadContext(hThread, &ctx) != FALSE;
    }

    ResumeThread(hThread);
    CloseHandle(hThread);

    if (!ok) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    ok = WaitForModuleLoad(pid, dllPath);
    VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return ok;
}

bool InjectDLL(DWORD pid, const std::string& dllPath, int method, bool eraseHeaders) {
    switch (method) {
    case 0: return InjectLoadLibrary(pid, dllPath);
    case 1: return ManualMap(pid, dllPath, eraseHeaders);
    case 2: return InjectNtCreateThreadEx(pid, dllPath);
    case 3: return InjectQueueUserAPC(pid, dllPath);
    case 4: return InjectRtlCreateUserThread(pid, dllPath);
    case 5: return InjectLoadLibraryW(pid, dllPath);
    case 6: return InjectThreadHijack(pid, dllPath);
    default: return false;
    }
}
