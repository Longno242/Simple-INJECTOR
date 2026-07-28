#include "Process.h"

#include <tlhelp32.h>
#include <algorithm>
#include <fstream>

bool IsProcess64Bit(DWORD pid) {
#ifdef _WIN64
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return true;
    BOOL wow64 = FALSE;
    if (!IsWow64Process(hProc, &wow64)) {
        CloseHandle(hProc);
        return true;
    }
    CloseHandle(hProc);
    return wow64 == FALSE;
#else
    (void)pid;
    return false;
#endif
}

WORD GetPeMachine(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return 0;
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    file.seekg(dos.e_lfanew);
    IMAGE_NT_HEADERS nt{};
    file.read(reinterpret_cast<char*>(&nt), sizeof(nt));
    if (!file || nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt.FileHeader.Machine;
}

bool IsDll64Bit(const std::string& path) {
    return GetPeMachine(path) == IMAGE_FILE_MACHINE_AMD64;
}

bool DllMatchesProcessArch(const std::string& dllPath, DWORD pid) {
    const WORD machine = GetPeMachine(dllPath);
    if (machine == 0) return false;
    const bool dll64 = machine == IMAGE_FILE_MACHINE_AMD64;
    const bool dll32 = machine == IMAGE_FILE_MACHINE_I386;
    if (!dll64 && !dll32) return false;
    return dll64 == IsProcess64Bit(pid);
}

std::vector<ProcessInfo> GetProcessList() {
    std::vector<ProcessInfo> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return procs;

    PROCESSENTRY32 pe{ sizeof(PROCESSENTRY32) };
    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            if (name == "System" || name == "svchost.exe" || name == "csrss.exe" || name == "smss.exe" ||
                name == "services.exe" || name == "lsass.exe" || name == "winlogon.exe" ||
                name == "Registry" || name == "Idle")
                continue;
            ProcessInfo info;
            info.name = std::move(name);
            info.pid = pe.th32ProcessID;
            info.is64 = IsProcess64Bit(info.pid);
            procs.push_back(std::move(info));
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    std::ranges::sort(procs, {}, &ProcessInfo::name);
    return procs;
}
