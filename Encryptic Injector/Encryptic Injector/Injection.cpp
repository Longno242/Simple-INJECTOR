#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <format>
#include <atomic>
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <cctype>
#include <wchar.h>
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/backends/imgui_impl_win32.h"
#include "imgui/backends/imgui_impl_dx11.h"
#include <d3d11.h>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "dwmapi.lib")
#include <dwmapi.h>

#ifdef _CONSOLE
int main() { return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOWDEFAULT); }
#endif

HWND g_hwnd = nullptr;
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
IDXGISwapChain* g_pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

struct AppState {
    bool running = true;
    char dll_path[512] = "";
    std::string selected_dll;
    std::string selected_process;
    DWORD selected_pid = 0;
    std::vector<std::pair<std::string, DWORD>> processes;
    char process_filter[256] = "";
    bool auto_close = false;
    int injection_method = 0;
    bool erase_pe_headers = true;
    std::string status_message;
    float status_timer = 0.0f;
    int status_type = 0;
    bool injecting = false;
};

static AppState g_state;
static ImFont* g_fontBody = nullptr;

namespace Theme {
    constexpr ImU32 Bg        = IM_COL32(13, 13, 13, 255);
    constexpr ImU32 Surface   = IM_COL32(22, 22, 22, 255);
    constexpr ImU32 SurfaceHi = IM_COL32(32, 32, 32, 255);
    constexpr ImU32 Border    = IM_COL32(48, 48, 48, 255);
    constexpr ImU32 Text      = IM_COL32(220, 220, 220, 255);
    constexpr ImU32 TextDim   = IM_COL32(130, 130, 130, 255);
    constexpr ImU32 TextMuted = IM_COL32(90, 90, 90, 255);
    constexpr ImU32 Accent    = IM_COL32(180, 180, 180, 255);
    constexpr ImU32 Success   = IM_COL32(160, 200, 160, 255);
    constexpr ImU32 Error     = IM_COL32(200, 140, 140, 255);
}

static std::string ToLowerAscii(const std::string& s) {
    std::string out; out.reserve(s.size());
    for (unsigned char c : s) out.push_back((char)std::tolower(c));
    return out;
}

static bool IsDllFilePath(const char* path) {
    if (!path) return false;
    std::string p(path);
    auto pos = p.find_last_of('.');
    if (pos == std::string::npos) return false;
    std::string ext = ToLowerAscii(p.substr(pos));
    return ext == ".dll";
}

std::string GetLastErrorAsString() {
    DWORD err = GetLastError();
    if (err == 0) return "Unknown error";
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr, err, 0, (LPSTR)&buf, 0, nullptr);
    std::string msg(buf);
    LocalFree(buf);
    return msg;
}

std::vector<std::pair<std::string, DWORD>> GetProcessList() {
    std::vector<std::pair<std::string, DWORD>> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return procs;

    PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            if (name != "System" && name != "svchost.exe" && name != "csrss.exe" && name != "smss.exe" && name != "services.exe" && name != "lsass.exe" && name != "winlogon.exe" && name != "Registry" && name != "Idle") procs.emplace_back(name, pe.th32ProcessID);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    std::ranges::sort(procs, {}, &std::pair<std::string, DWORD>::first);
    return procs;
}

bool InjectLoadLibrary(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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
    return exitCode != 0;
}

static LPVOID RemoteAllocAnsiPath(HANDLE hProc, const std::string& path) {
    SIZE_T size = path.size() + 1;
    LPVOID alloc = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc) return nullptr;
    if (!WriteProcessMemory(hProc, alloc, path.c_str(), size, nullptr)) {
        VirtualFreeEx(hProc, alloc, 0, MEM_RELEASE);
        return nullptr;
    }
    return alloc;
}

static LPVOID RemoteAllocWidePath(HANDLE hProc, const std::string& path) {
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

static std::string GetDllFileName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    return pos == std::string::npos ? path : path.substr(pos + 1);
}

static bool IsModuleLoaded(DWORD pid, const std::string& dllPath) {
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

static bool WaitForModuleLoad(DWORD pid, const std::string& dllPath, DWORD timeoutMs = 8000) {
    DWORD elapsed = 0;
    while (elapsed < timeoutMs) {
        if (IsModuleLoaded(pid, dllPath)) return true;
        Sleep(100);
        elapsed += 100;
    }
    return false;
}

static bool FinishLoadLibraryThread(HANDLE hProc, LPVOID alloc, HANDLE hThread) {
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

bool InjectLoadLibraryW(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
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

static bool ApplyRelocations(uint8_t* image, IMAGE_NT_HEADERS* nt, uintptr_t delta) {
    if (!delta) return true;
    IMAGE_DATA_DIRECTORY* relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocDir->Size) return true;

    auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + relocDir->VirtualAddress);
    auto* relocEnd = reinterpret_cast<uint8_t*>(reloc) + relocDir->Size;

    while (reinterpret_cast<uint8_t*>(reloc) < relocEnd && reloc->SizeOfBlock) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = reinterpret_cast<WORD*>(reloc + 1);

        for (DWORD i = 0; i < count; ++i) {
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0xFFF;
            uint8_t* patchAddr = image + reloc->VirtualAddress + offset;

#ifdef _WIN64
            if (type == IMAGE_REL_BASED_DIR64) {
                *reinterpret_cast<uintptr_t*>(patchAddr) += delta;
            }
#else
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                *reinterpret_cast<DWORD*>(patchAddr) += static_cast<DWORD>(delta);
            }
#endif
            else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                // padding entry
            }
        }
        reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
    }
    return true;
}

static bool ResolveImports(uint8_t* image, IMAGE_NT_HEADERS* nt) {
    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir->Size) return true;

    auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image + importDir->VirtualAddress);
    while (importDesc->Name) {
        const char* dllName = reinterpret_cast<const char*>(image + importDesc->Name);
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) return false;

        auto* thunk = reinterpret_cast<uintptr_t*>(image + importDesc->FirstThunk);
        auto* origThunk = importDesc->OriginalFirstThunk
            ? reinterpret_cast<uintptr_t*>(image + importDesc->OriginalFirstThunk)
            : thunk;

        while (*origThunk) {
            FARPROC func = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL(*origThunk)) {
                func = GetProcAddress(hMod, MAKEINTRESOURCEA(IMAGE_ORDINAL(*origThunk)));
            }
            else {
                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image + (*origThunk));
                func = GetProcAddress(hMod, ibn->Name);
            }
            if (!func) return false;
            *thunk = reinterpret_cast<uintptr_t>(func);
            ++origThunk;
            ++thunk;
        }
        ++importDesc;
    }
    return true;
}

static bool CallRemoteDllMain(HANDLE hProc, uintptr_t remoteBase, uintptr_t entryPoint) {
#ifdef _WIN64
    uint8_t shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
        0xBA, 0x01, 0x00, 0x00, 0x00,
        0x4D, 0x31, 0xC0,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *reinterpret_cast<uintptr_t*>(&shellcode[6]) = remoteBase;
    *reinterpret_cast<uintptr_t*>(&shellcode[24]) = entryPoint;
#else
    uint8_t shellcode[] = {
        0x6A, 0x00,
        0x6A, 0x01,
        0x68, 0, 0, 0, 0,
        0xB8, 0, 0, 0, 0,
        0xFF, 0xD0,
        0xC3
    };
    *reinterpret_cast<DWORD*>(&shellcode[5]) = static_cast<DWORD>(remoteBase);
    *reinterpret_cast<DWORD*>(&shellcode[10]) = static_cast<DWORD>(entryPoint);
#endif

    LPVOID remoteShell = VirtualAllocEx(hProc, nullptr, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteShell) return false;

    if (!WriteProcessMemory(hProc, remoteShell, shellcode, sizeof(shellcode), nullptr)) {
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteShell), nullptr, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
    return exitCode != 0;
}

bool ManualMap(DWORD pid, const std::string& dllPath, bool eraseHeaders) {
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) return false;
    size_t fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0);
    std::vector<uint8_t> fileData(fileSize);
    if (!file.read(reinterpret_cast<char*>(fileData.data()), fileSize)) return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(fileData.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

#ifdef _WIN64
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
#else
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) return false;
#endif

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    std::vector<uint8_t> image(imageSize, 0);

    memcpy(image.data(), fileData.data(), nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->SizeOfRawData == 0) continue;
        memcpy(image.data() + section->VirtualAddress,
            fileData.data() + section->PointerToRawData,
            section->SizeOfRawData);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    LPVOID remoteBase = VirtualAllocEx(hProc,
        reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase),
        imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteBase)
        remoteBase = VirtualAllocEx(hProc, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!remoteBase) { CloseHandle(hProc); return false; }

    uintptr_t delta = reinterpret_cast<uintptr_t>(remoteBase) - nt->OptionalHeader.ImageBase;
    if (!ApplyRelocations(image.data(), nt, delta)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (!ResolveImports(image.data(), nt)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteBase, image.data(), imageSize, nullptr)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (eraseHeaders) {
        std::vector<uint8_t> zeros(nt->OptionalHeader.SizeOfHeaders, 0);
        WriteProcessMemory(hProc, remoteBase, zeros.data(), zeros.size(), nullptr);
    }

    uintptr_t entryPoint = reinterpret_cast<uintptr_t>(remoteBase) + nt->OptionalHeader.AddressOfEntryPoint;
    bool ok = CallRemoteDllMain(hProc, reinterpret_cast<uintptr_t>(remoteBase), entryPoint);

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

static void DrawSectionLabel(const char* text) {
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextDim);
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();
}

static bool FlatButton(const char* label, ImVec2 size, bool enabled = true) {
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton(label, size);
    bool hovered = ImGui::IsItemHovered();
    bool clicked = enabled && hovered && ImGui::IsMouseReleased(0);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImU32 bg = !enabled ? Theme::Surface : (hovered ? Theme::SurfaceHi : Theme::Surface);
    dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), bg, 4.0f);
    dl->AddRect(pos, ImVec2(pos.x + size.x, pos.y + size.y), Theme::Border, 4.0f);
    ImVec2 ts = ImGui::CalcTextSize(label);
    dl->AddText(ImVec2(pos.x + (size.x - ts.x) * 0.5f, pos.y + (size.y - ts.y) * 0.5f),
        enabled ? Theme::Text : Theme::TextMuted, label);
    return clicked;
}

void SetupModernStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    auto& c = style.Colors;
    style.WindowRounding = 0.0f;
    style.ChildRounding = 4.0f;
    style.FrameRounding = 4.0f;
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.WindowPadding = ImVec2(14, 14);
    style.FramePadding = ImVec2(8, 5);
    style.ItemSpacing = ImVec2(8, 6);
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.ScrollbarSize = 10.0f;

    c[ImGuiCol_Text] = ImColor(Theme::Text);
    c[ImGuiCol_TextDisabled] = ImColor(Theme::TextMuted);
    c[ImGuiCol_WindowBg] = ImColor(Theme::Bg);
    c[ImGuiCol_ChildBg] = ImColor(Theme::Surface);
    c[ImGuiCol_PopupBg] = ImVec4(0.1f, 0.1f, 0.1f, 1.0f);
    c[ImGuiCol_Border] = ImColor(Theme::Border);
    c[ImGuiCol_FrameBg] = ImVec4(0.12f, 0.12f, 0.12f, 1.0f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.16f, 0.16f, 0.16f, 1.0f);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.18f, 0.18f, 0.18f, 1.0f);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0.08f, 0.08f, 0.08f, 1.0f);
    c[ImGuiCol_ScrollbarGrab] = ImVec4(0.25f, 0.25f, 0.25f, 1.0f);
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.32f, 0.32f, 0.32f, 1.0f);
    c[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.4f, 0.4f, 0.4f, 1.0f);
    c[ImGuiCol_CheckMark] = ImVec4(0.85f, 0.85f, 0.85f, 1.0f);
    c[ImGuiCol_Button] = ImVec4(0.14f, 0.14f, 0.14f, 1.0f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.2f, 0.2f, 0.2f, 1.0f);
    c[ImGuiCol_ButtonActive] = ImVec4(0.24f, 0.24f, 0.24f, 1.0f);
    c[ImGuiCol_Header] = ImVec4(0.18f, 0.18f, 0.18f, 1.0f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.22f, 0.22f, 0.22f, 1.0f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.26f, 0.26f, 1.0f);
    c[ImGuiCol_Separator] = ImColor(Theme::Border);
}

void RenderUI() {
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 display = io.DisplaySize;

    ImGui::GetBackgroundDrawList()->AddRectFilled(ImVec2(0, 0), display, Theme::Bg);

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(display);
    ImGui::Begin("##Main", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse);

    const float pad = 14.0f;
    const float w = display.x - pad * 2;
    const float rowH = ImGui::GetFrameHeight();
    const float footerH = rowH + 34.0f + 28.0f + pad + 8.0f; // extra for method combo

    ImGui::SetCursorPos(ImVec2(pad, pad));
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::Text);
    ImGui::Text("Encryptic Injector");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::SetCursorPosX(w + pad - 28);
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextMuted);
    ImGui::Text("v3.0");
    ImGui::PopStyleColor();

    ImGui::SetCursorPosX(pad);
    ImGui::Separator();

    // DLL
    ImGui::SetCursorPosX(pad);
    DrawSectionLabel("DLL");
    ImGui::SetCursorPosX(pad);
    ImGui::PushItemWidth(w - 76);
    ImGui::InputTextWithHint("##dll", "Select a .dll file...", g_state.dll_path,
        IM_ARRAYSIZE(g_state.dll_path), ImGuiInputTextFlags_ReadOnly);
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (FlatButton("Browse##dll", ImVec2(68, ImGui::GetFrameHeight()))) {
        OPENFILENAMEA ofn = {};
        char szFile[512] = {};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hwnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
        if (GetOpenFileNameA(&ofn)) {
            strcpy_s(g_state.dll_path, szFile);
            g_state.selected_dll = szFile;
        }
    }

    // Process list
    ImGui::SetCursorPosX(pad);
    DrawSectionLabel("Process");
    ImGui::SetCursorPosX(pad);
    ImGui::PushItemWidth(w - 56);
    ImGui::InputTextWithHint("##filter", "Filter...", g_state.process_filter, sizeof(g_state.process_filter));
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (FlatButton("Refresh", ImVec2(48, ImGui::GetFrameHeight())))
        g_state.processes = GetProcessList();

    ImGui::SetCursorPosX(pad);
    ImGui::BeginChild("##proclist", ImVec2(w, ImMax(120.0f, display.y - ImGui::GetCursorPosY() - footerH - 118.0f)), true);
    if (g_state.processes.empty()) g_state.processes = GetProcessList();

    std::string filterLower = ToLowerAscii(g_state.process_filter);
    for (const auto& [name, pid] : g_state.processes) {
        if (!filterLower.empty()) {
            std::string nameLower = ToLowerAscii(name);
            std::string pidStr = std::to_string(pid);
            if (nameLower.find(filterLower) == std::string::npos && pidStr.find(filterLower) == std::string::npos)
                continue;
        }
        bool selected = (g_state.selected_pid == pid);
        ImGui::PushStyleColor(ImGuiCol_Header, Theme::SurfaceHi);
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, Theme::SurfaceHi);
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, Theme::SurfaceHi);
        if (ImGui::Selectable(std::format("{}  ({})", name, pid).c_str(), selected))
            g_state.selected_pid = pid, g_state.selected_process = name;
        ImGui::PopStyleColor(3);
    }
    ImGui::EndChild();

    // Method & options
    ImGui::SetCursorPosX(pad);
    DrawSectionLabel("Method");
    ImGui::SetCursorPosX(pad);
    const char* methods[] = {
        "LoadLibrary (Standard)",
        "Manual Map (Stealth)",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "RtlCreateUserThread",
        "LoadLibraryW",
        "Thread Hijack"
    };
    ImGui::PushItemWidth(w);
    ImGui::Combo("##method", &g_state.injection_method, methods, IM_ARRAYSIZE(methods));
    ImGui::PopItemWidth();

    ImGui::SetCursorPosX(pad);
    ImGui::Checkbox("Auto-close on success", &g_state.auto_close);
    ImGui::SameLine(0, 24);
    if (g_state.injection_method == 1) {
        ImGui::Checkbox("Erase PE headers (manual map)", &g_state.erase_pe_headers);
    }
    else {
        ImGui::BeginDisabled();
        bool dummy = g_state.erase_pe_headers;
        ImGui::Checkbox("Erase PE headers (manual map)", &dummy);
        ImGui::EndDisabled();
    }

    ImGui::SetCursorPosX(pad);
    ImGui::Separator();

    // Inject
    bool canInject = g_state.selected_pid != 0 && strlen(g_state.dll_path) > 0 && !g_state.injecting;
    ImGui::SetCursorPosX(pad);
    if (g_state.injecting) {
        ImGui::PushStyleColor(ImGuiCol_Button, Theme::Surface);
        ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextDim);
        ImGui::Button("Injecting...", ImVec2(w, 34));
        ImGui::PopStyleColor(2);
    }
    else if (FlatButton(canInject ? "Inject" : "Select DLL and process", ImVec2(w, 34), canInject)) {
        g_state.injecting = true;
        bool success = InjectDLL(g_state.selected_pid, g_state.selected_dll,
            g_state.injection_method, g_state.erase_pe_headers);
        g_state.injecting = false;
        if (success) {
            g_state.status_message = std::format("Injected into {}", g_state.selected_process);
            g_state.status_type = 1;
            g_state.status_timer = 4.0f;
            if (g_state.auto_close) g_state.running = false;
        }
        else {
            g_state.status_message = "Failed: " + GetLastErrorAsString();
            g_state.status_type = 2;
            g_state.status_timer = 4.0f;
        }
    }

    // Status
    ImGui::SetCursorPosX(pad);
    if (g_state.status_timer > 0.0f) {
        g_state.status_timer -= io.DeltaTime;
        ImU32 col = (g_state.status_type == 1) ? Theme::Success : Theme::Error;
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextWrapped("%s", g_state.status_message.c_str());
        ImGui::PopStyleColor();
    }
    else {
        ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextMuted);
        ImGui::TextUnformatted("Ready");
        ImGui::PopStyleColor();
    }

    ImGui::End();
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createFlags = 0;
    D3D_FEATURE_LEVEL featureLevels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL selected;

    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createFlags,
        featureLevels, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &selected, &g_pd3dDeviceContext) != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wParam;
        UINT count = DragQueryFileA(hDrop, 0xFFFFFFFF, nullptr, 0);
        for (UINT i = 0; i < count; ++i) {
            char filePath[MAX_PATH];
            if (DragQueryFileA(hDrop, i, filePath, MAX_PATH)) {
                if (IsDllFilePath(filePath)) {
                    strcpy_s(g_state.dll_path, filePath);
                    g_state.selected_dll = filePath;
                    g_state.status_message = "DLL loaded";
                    g_state.status_type = 1;
                    g_state.status_timer = 2.0f;
                }
            }
        }
        DragFinish(hDrop);
        return 0;
    }
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L,
                      GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
                      TEXT("Encryptic Injector"), nullptr };
    RegisterClassEx(&wc);

    g_hwnd = CreateWindow(wc.lpszClassName, TEXT("Encryptic Injector"),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        200, 120, 520, 600, nullptr, nullptr, wc.hInstance, nullptr);

    BOOL darkMode = TRUE;
    DwmSetWindowAttribute(g_hwnd, 20, &darkMode, sizeof(darkMode));

    if (!CreateDeviceD3D(g_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    DragAcceptFiles(g_hwnd, TRUE);
    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    ImFontConfig fc;
    fc.OversampleH = 2;
    fc.OversampleV = 1;
    g_fontBody = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 13.0f, &fc);
    if (!g_fontBody) g_fontBody = io.Fonts->AddFontDefault();
    io.FontDefault = g_fontBody;

    SetupModernStyle();

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    MSG msg{};
    while (g_state.running && msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderUI();

        ImGui::Render();
        const float clearColor[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(g_hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}
