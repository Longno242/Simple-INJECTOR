#include "Injection.h"
#include "InjectionCommon.h"

#include <fstream>
#include <vector>
#include <cstring>

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
                // padding
            }
        }
        reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
    }
    return true;
}

static bool ResolveImports(HANDLE hProc, DWORD pid, uint8_t* image, IMAGE_NT_HEADERS* nt) {
    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir->Size) return true;

    auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image + importDir->VirtualAddress);
    while (importDesc->Name) {
        const char* dllName = reinterpret_cast<const char*>(image + importDesc->Name);
        HMODULE hLocal = LoadLibraryA(dllName);
        if (!hLocal) return false;

        uintptr_t remoteModBase = GetRemoteModuleBase(pid, dllName);
        if (!remoteModBase) {
            if (!RemoteLoadLibraryA(hProc, dllName)) return false;
            remoteModBase = GetRemoteModuleBase(pid, dllName);
            if (!remoteModBase) return false;
        }

        const uintptr_t localModBase = reinterpret_cast<uintptr_t>(hLocal);

        auto* thunk = reinterpret_cast<uintptr_t*>(image + importDesc->FirstThunk);
        auto* origThunk = importDesc->OriginalFirstThunk
            ? reinterpret_cast<uintptr_t*>(image + importDesc->OriginalFirstThunk)
            : thunk;

        while (*origThunk) {
            FARPROC funcLocal = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL(*origThunk)) {
                funcLocal = GetProcAddress(hLocal, MAKEINTRESOURCEA(IMAGE_ORDINAL(*origThunk)));
            }
            else {
                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image + (*origThunk));
                funcLocal = GetProcAddress(hLocal, ibn->Name);
            }
            if (!funcLocal) return false;
            const uintptr_t rva = reinterpret_cast<uintptr_t>(funcLocal) - localModBase;
            *thunk = remoteModBase + rva;
            ++origThunk;
            ++thunk;
        }
        ++importDesc;
    }
    return true;
}

static DWORD SectionCharacteristicsToProtect(DWORD characteristics) {
    const bool exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read) return PAGE_EXECUTE_READ;
    if (exec) return PAGE_EXECUTE;
    if (write) return PAGE_READWRITE;
    if (read) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

static bool ApplyRemoteSectionProtections(HANDLE hProc, uintptr_t remoteBase, IMAGE_NT_HEADERS* nt) {
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->Misc.VirtualSize == 0) continue;
        DWORD protect = SectionCharacteristicsToProtect(section->Characteristics);
        LPVOID secAddr = reinterpret_cast<LPVOID>(remoteBase + section->VirtualAddress);
        SIZE_T secSize = section->Misc.VirtualSize;
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(hProc, secAddr, secSize, protect, &oldProtect))
            return false;
    }
    return true;
}

// Encryptic custom remote call stub — frame-pointer prologue + call r11 (not the usual pub snippet).
#ifdef _WIN64
static constexpr size_t kRemoteCallStubSize = 47;
static constexpr size_t kPatchRemoteCallBase = 10;
static constexpr size_t kPatchRemoteCallReason = 21;
static constexpr size_t kPatchRemoteCallFunc = 30;

static void BuildCustomRemoteCallStub(uint8_t* out, uintptr_t arg0, uintptr_t arg1, uintptr_t, uintptr_t func) {
    static const uint8_t kTemplate[kRemoteCallStubSize] = {
        0x55, 0x48, 0x89, 0xE5,
        0x48, 0x83, 0xEC, 0x40,
        0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
        0x45, 0x33, 0xC0,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0x89, 0xC2,
        0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0,
        0x41, 0xFF, 0xD3,
        0x48, 0x83, 0xC4, 0x40,
        0x5D, 0xC3
    };
    memcpy(out, kTemplate, sizeof(kTemplate));
    *reinterpret_cast<uintptr_t*>(&out[kPatchRemoteCallBase]) = arg0;
    *reinterpret_cast<uintptr_t*>(&out[kPatchRemoteCallFunc]) = func;
    if (arg1 != 1)
        *reinterpret_cast<DWORD*>(&out[kPatchRemoteCallReason]) = static_cast<DWORD>(arg1);
}
#else
static constexpr size_t kRemoteCallStubSize = 17;
static constexpr size_t kPatchRemoteCallBase = 1;
static constexpr size_t kPatchRemoteCallReason = 6;
static constexpr size_t kPatchRemoteCallFunc = 10;

static void BuildCustomRemoteCallStub(uint8_t* out, uintptr_t arg0, uintptr_t arg1, uintptr_t, uintptr_t func) {
    static const uint8_t kTemplate[kRemoteCallStubSize] = {
        0x68, 0, 0, 0, 0,
        0x6A, 0x01,
        0x6A, 0x00,
        0xB8, 0, 0, 0, 0,
        0xFF, 0xD0,
        0xC3
    };
    memcpy(out, kTemplate, sizeof(kTemplate));
    *reinterpret_cast<DWORD*>(&out[kPatchRemoteCallBase]) = static_cast<DWORD>(arg0);
    *reinterpret_cast<DWORD*>(&out[kPatchRemoteCallFunc]) = static_cast<DWORD>(func);
    out[kPatchRemoteCallReason] = static_cast<uint8_t>(arg1 & 0xFF);
}
#endif

static bool RunRemoteCall(HANDLE hProc, uintptr_t func, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2) {
    uint8_t shellcode[kRemoteCallStubSize]{};
    BuildCustomRemoteCallStub(shellcode, arg0, arg1, arg2, func);

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

static bool CallRemoteDllMain(HANDLE hProc, uintptr_t remoteBase, uintptr_t entryPoint) {
    return RunRemoteCall(hProc, entryPoint, remoteBase, 1, 0);
}

static bool RunRemoteTlsCallbacks(HANDLE hProc, uint8_t* image, IMAGE_NT_HEADERS* nt, uintptr_t remoteBase) {
    IMAGE_DATA_DIRECTORY* tlsDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tlsDir->Size) return true;

#ifdef _WIN64
    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(image + tlsDir->VirtualAddress);
    ULONG_PTR callbacksVa = tls->AddressOfCallBacks;
#else
    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY32*>(image + tlsDir->VirtualAddress);
    ULONG_PTR callbacksVa = tls->AddressOfCallBacks;
#endif
    if (!callbacksVa) return true;

    const size_t listOffset = static_cast<size_t>(callbacksVa - remoteBase);
    if (listOffset + sizeof(uintptr_t) > nt->OptionalHeader.SizeOfImage) return false;

    auto* callbackPtr = reinterpret_cast<uintptr_t*>(image + listOffset);
    while (*callbackPtr) {
        if (!RunRemoteCall(hProc, *callbackPtr, remoteBase, 1, 0))
            return false;
        ++callbackPtr;
    }
    return true;
}

static bool VerifyRemoteMappedImage(HANDLE hProc, uintptr_t remoteBase, bool headersErased) {
    if (headersErased) return true;
    uint16_t magic = 0;
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteBase), &magic, sizeof(magic), &read))
        return false;
    return read == sizeof(magic) && magic == IMAGE_DOS_SIGNATURE;
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

    HANDLE hProc = OpenTargetProcess(pid, kAccessInjectThread);
    if (!hProc) return false;

    LPVOID remoteBase = VirtualAllocEx(hProc,
        reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase),
        imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteBase)
        remoteBase = VirtualAllocEx(hProc, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteBase) { CloseHandle(hProc); return false; }

    uintptr_t delta = reinterpret_cast<uintptr_t>(remoteBase) - nt->OptionalHeader.ImageBase;
    if (!ApplyRelocations(image.data(), nt, delta)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (!ResolveImports(hProc, pid, image.data(), nt)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteBase, image.data(), imageSize, nullptr)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (!ApplyRemoteSectionProtections(hProc, reinterpret_cast<uintptr_t>(remoteBase), nt)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    const uintptr_t mappedBase = reinterpret_cast<uintptr_t>(remoteBase);

    if (!RunRemoteTlsCallbacks(hProc, image.data(), nt, mappedBase)) {
        VirtualFreeEx(hProc, remoteBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    if (eraseHeaders) {
        std::vector<uint8_t> zeros(nt->OptionalHeader.SizeOfHeaders, 0);
        WriteProcessMemory(hProc, remoteBase, zeros.data(), zeros.size(), nullptr);
    }

    uintptr_t entryPoint = mappedBase + nt->OptionalHeader.AddressOfEntryPoint;
    bool ok = CallRemoteDllMain(hProc, mappedBase, entryPoint);
    ok = ok && VerifyRemoteMappedImage(hProc, mappedBase, eraseHeaders);

    CloseHandle(hProc);
    return ok;
}
