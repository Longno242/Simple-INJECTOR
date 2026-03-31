#include <windows.h>
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
    std::string status_message;
    float status_timer = 0.0f;
    int status_type = 0;
    float animation_offset = 0.0f;
    bool show_settings = false;
    bool show_about = false;
};

static AppState g_state;

namespace Colors {
    constexpr ImU32 DarkBg = IM_COL32(18, 22, 27, 255);
    constexpr ImU32 DarkerBg = IM_COL32(13, 17, 22, 255);
    constexpr ImU32 CardBg = IM_COL32(28, 32, 37, 255);
    constexpr ImU32 HoverBg = IM_COL32(38, 42, 47, 255);
    constexpr ImU32 Accent = IM_COL32(88, 156, 255, 255);
    constexpr ImU32 AccentHover = IM_COL32(108, 176, 255, 255);
    constexpr ImU32 Success = IM_COL32(46, 204, 113, 255);
    constexpr ImU32 Error = IM_COL32(231, 76, 60, 255);
    constexpr ImU32 Warning = IM_COL32(241, 196, 15, 255);
    constexpr ImU32 TextPrimary = IM_COL32(236, 240, 241, 255);
    constexpr ImU32 TextSecondary = IM_COL32(149, 165, 166, 255);
    constexpr ImU32 Border = IM_COL32(52, 58, 64, 255);
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

bool ManualMap(DWORD pid, const std::string& dllPath) {
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) return false;
    size_t fileSize = file.tellg();
    file.seekg(0);
    std::vector<uint8_t> dllData(fileSize);
    file.read(reinterpret_cast<char*>(dllData.data()), fileSize);

    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dllData.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(dllData.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return false;

    LPVOID base = VirtualAllocEx(hProc, nullptr, nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) { CloseHandle(hProc); return false; }

    WriteProcessMemory(hProc, base, dllData.data(), nt->OptionalHeader.SizeOfHeaders, nullptr);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (section->SizeOfRawData == 0) {
            section++;
            continue;
        }
        LPVOID secDest = (LPVOID)((uintptr_t)base + section->VirtualAddress);
        WriteProcessMemory(hProc, secDest, dllData.data() + section->PointerToRawData,
            section->SizeOfRawData, nullptr);
        section++;
    }

    uintptr_t delta = (uintptr_t)base - nt->OptionalHeader.ImageBase;
    if (delta) {
        IMAGE_DATA_DIRECTORY* relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size) {
            IMAGE_BASE_RELOCATION* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                dllData.data() + relocDir->VirtualAddress);

            while (reloc->SizeOfBlock) {
                WORD* typeOffset = (WORD*)((uintptr_t)reloc + sizeof(IMAGE_BASE_RELOCATION));
                DWORD entries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

                for (DWORD i = 0; i < entries; ++i) {
                    WORD entry = typeOffset[i];
                    WORD type = entry >> 12;
                    WORD offset = entry & 0xFFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        uintptr_t* patch = (uintptr_t*)((uintptr_t)base + reloc->VirtualAddress + offset);
                        DWORD64 temp = 0;
                        ReadProcessMemory(hProc, patch, &temp, sizeof(DWORD64), nullptr);
                        temp += delta;
                        WriteProcessMemory(hProc, patch, &temp, sizeof(DWORD64), nullptr);
                    }
                }
                reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)reloc + reloc->SizeOfBlock);
            }
        }
    }

    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size) {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            dllData.data() + importDir->VirtualAddress);

        while (importDesc->Name) {
            char* dllName = (char*)(dllData.data() + importDesc->Name);
            HMODULE hModule = LoadLibraryA(dllName);

            uintptr_t* thunk = (uintptr_t*)((uintptr_t)base + importDesc->FirstThunk);
            uintptr_t* origThunk = (uintptr_t*)((uintptr_t)base + importDesc->OriginalFirstThunk);

            while (*origThunk) {
                if (*origThunk & IMAGE_ORDINAL_FLAG) {
                    uintptr_t func = (uintptr_t)GetProcAddress(hModule, MAKEINTRESOURCEA(*origThunk & 0xFFFF));
                    WriteProcessMemory(hProc, thunk, &func, sizeof(uintptr_t), nullptr);
                }
                else {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dllData.data() + *origThunk);
                    uintptr_t func = (uintptr_t)GetProcAddress(hModule, ibn->Name);
                    WriteProcessMemory(hProc, thunk, &func, sizeof(uintptr_t), nullptr);
                }
                thunk++;
                origThunk++;
            }
            importDesc++;
        }
    }

    auto dllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))((uintptr_t)base + nt->OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)dllMain, base, 0, nullptr);

    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }

    CloseHandle(hProc);
    return true;
}

bool InjectDLL(DWORD pid, const std::string& dllPath, int method) {
    if (method == 0)
        return InjectLoadLibrary(pid, dllPath);
    else
        return ManualMap(pid, dllPath);
}

void SetupModernStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    auto& c = style.Colors;

    style.WindowRounding = 12.0f;
    style.ChildRounding = 8.0f;
    style.FrameRounding = 8.0f;
    style.PopupRounding = 8.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding = 6.0f;
    style.TabRounding = 6.0f;
    style.WindowPadding = ImVec2(20, 20);
    style.FramePadding = ImVec2(12, 8);
    style.ItemSpacing = ImVec2(12, 12);
    style.ItemInnerSpacing = ImVec2(8, 6);
    style.IndentSpacing = 25.0f;
    style.ScrollbarSize = 10.0f;
    style.GrabMinSize = 10.0f;
    style.WindowBorderSize = 1.0f;
    style.ChildBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.WindowTitleAlign = ImVec2(0.5f, 0.5f);
    style.TabRounding = 8.0f;
    style.ItemSpacing.x = 18.0f;
    style.ItemInnerSpacing.y = 10.0f;
    style.TabBorderSize = 1.0f;

    c[ImGuiCol_Text] = ImColor(Colors::TextPrimary);
    c[ImGuiCol_TextDisabled] = ImColor(Colors::TextSecondary);
    c[ImGuiCol_WindowBg] = ImColor(Colors::DarkBg);
    c[ImGuiCol_ChildBg] = ImColor(Colors::CardBg);
    c[ImGuiCol_PopupBg] = ImColor(Colors::CardBg);
    c[ImGuiCol_Border] = ImColor(Colors::Border);
    c[ImGuiCol_BorderShadow] = ImColor(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = ImColor(Colors::DarkerBg);
    c[ImGuiCol_FrameBgHovered] = ImColor(Colors::HoverBg);
    c[ImGuiCol_FrameBgActive] = ImColor(Colors::Accent);
    c[ImGuiCol_TitleBg] = ImColor(Colors::CardBg);
    c[ImGuiCol_TitleBgActive] = ImColor(Colors::Accent);
    c[ImGuiCol_TitleBgCollapsed] = ImColor(Colors::CardBg);
    c[ImGuiCol_MenuBarBg] = ImColor(Colors::CardBg);
    c[ImGuiCol_ScrollbarBg] = ImColor(Colors::DarkerBg);
    c[ImGuiCol_ScrollbarGrab] = ImColor(Colors::HoverBg);
    c[ImGuiCol_ScrollbarGrabHovered] = ImColor(Colors::Accent);
    c[ImGuiCol_ScrollbarGrabActive] = ImColor(Colors::AccentHover);
    c[ImGuiCol_CheckMark] = ImColor(Colors::Accent);
    c[ImGuiCol_SliderGrab] = ImColor(Colors::Accent);
    c[ImGuiCol_SliderGrabActive] = ImColor(Colors::AccentHover);
    c[ImGuiCol_Button] = ImColor(Colors::Accent);
    c[ImGuiCol_ButtonHovered] = ImColor(Colors::AccentHover);
    c[ImGuiCol_ButtonActive] = ImColor(Colors::Accent);
    c[ImGuiCol_Header] = ImColor(Colors::CardBg);
    c[ImGuiCol_HeaderHovered] = ImColor(Colors::HoverBg);
    c[ImGuiCol_HeaderActive] = ImColor(Colors::Accent);
    c[ImGuiCol_Separator] = ImColor(Colors::Border);
    c[ImGuiCol_SeparatorHovered] = ImColor(Colors::Accent);
    c[ImGuiCol_SeparatorActive] = ImColor(Colors::AccentHover);
    c[ImGuiCol_ResizeGrip] = ImColor(Colors::Border);
    c[ImGuiCol_ResizeGripHovered] = ImColor(Colors::Accent);
    c[ImGuiCol_ResizeGripActive] = ImColor(Colors::AccentHover);
    c[ImGuiCol_Tab] = ImColor(Colors::CardBg);
    c[ImGuiCol_TabHovered] = ImColor(Colors::HoverBg);
    c[ImGuiCol_TabActive] = ImColor(Colors::Accent);
    c[ImGuiCol_TabUnfocused] = ImColor(Colors::CardBg);
    c[ImGuiCol_TabUnfocusedActive] = ImColor(Colors::Accent);
    c[ImGuiCol_PlotLines] = ImColor(Colors::Accent);
    c[ImGuiCol_PlotLinesHovered] = ImColor(Colors::AccentHover);
    c[ImGuiCol_PlotHistogram] = ImColor(Colors::Accent);
    c[ImGuiCol_PlotHistogramHovered] = ImColor(Colors::AccentHover);
    {
        ImVec4 col = ImColor(Colors::Accent).Value;
        col.w *= 0.35f;
        c[ImGuiCol_TextSelectedBg] = col;
    }
    {
        ImVec4 col = ImColor(Colors::Accent).Value;
        col.w *= 0.5f;
        c[ImGuiCol_DragDropTarget] = col;
    }
    c[ImGuiCol_NavHighlight] = ImColor(Colors::Accent);
    c[ImGuiCol_NavWindowingHighlight] = ImColor(Colors::Accent);
}

void RenderUI() {
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 display = io.DisplaySize;

    ImDrawList* bg = ImGui::GetBackgroundDrawList();
    bg->AddRectFilledMultiColor(ImVec2(0, 0), display,
        IM_COL32(18, 22, 27, 255), IM_COL32(18, 22, 27, 255),
        IM_COL32(13, 17, 22, 255), IM_COL32(13, 17, 22, 255));

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(display);
    ImGui::Begin("##MainWindow", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar);

    float windowWidth = ImGui::GetWindowWidth();
    float windowHeight = ImGui::GetWindowHeight();

    ImGui::BeginChild("Header", ImVec2(windowWidth - 40, 80), false);
    ImDrawList* headerDraw = ImGui::GetWindowDrawList();
    ImVec2 headerPos = ImGui::GetCursorScreenPos();
    headerDraw->AddRectFilled(headerPos, ImVec2(headerPos.x + windowWidth - 40, headerPos.y + 80),
        IM_COL32(28, 32, 37, 255), 12.0f, ImDrawFlags_RoundCornersTop);

    ImGui::SetCursorPosX(20);
    ImGui::SetCursorPosY(20);
    ImGui::PushFont(io.Fonts->Fonts[0]);
    ImGui::TextColored(ImColor(Colors::Accent), "Encryptic");
    ImGui::SameLine(0, 8);
    ImGui::TextColored(ImColor(Colors::TextPrimary), "INJECTOR");
    ImGui::PopFont();
    ImGui::SameLine(windowWidth - 180);
    ImGui::SetCursorPosY(28);
    ImGui::TextColored(ImColor(Colors::TextSecondary), "v2.0 | Modern Injection Framework");
    ImGui::EndChild();
    ImGui::Spacing();

    float spacing = 20.0f;
    float available = windowWidth - 40.0f - spacing;
    float leftWidth = available * 0.5f;
    float rightWidth = available * 0.5f;

    ImGui::BeginChild("LeftColumn", ImVec2(leftWidth, windowHeight - 160), false);
    ImGui::BeginChild("DLLCard", ImVec2(leftWidth - 20, 200), true);
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(15);
    ImGui::TextColored(ImColor(Colors::Accent), "DLL MODULE");
    ImGui::SetCursorPosY(45);
    ImGui::Separator();
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(70);
    ImGui::PushItemWidth(leftWidth - 120);
    ImGui::InputText("##dllpath", g_state.dll_path, IM_ARRAYSIZE(g_state.dll_path), ImGuiInputTextFlags_ReadOnly);
    ImGui::PopItemWidth();

    ImGui::SameLine();
    if (ImGui::Button("BROWSE", ImVec2(80, 32))) {
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

    if (strlen(g_state.dll_path) > 0) {
        ImGui::SetCursorPosX(15);
        ImGui::SetCursorPosY(115);
        ImGui::TextColored(ImColor(Colors::TextSecondary), "✓ %s",
            g_state.selected_dll.substr(g_state.selected_dll.find_last_of("\\") + 1).c_str());
    }

    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(150);
    {
        ImVec4 col = ImColor(Colors::TextSecondary).Value;
        col.w *= 0.6f;
        ImGui::TextColored(col, "Drag & drop DLL files here");
    }
    ImGui::EndChild();
    ImGui::Spacing();
    ImGui::BeginChild("ProcessCard", ImVec2(leftWidth - 20, windowHeight - 400), true);
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(15);
    ImGui::TextColored(ImColor(Colors::Accent), "TARGET PROCESS");
    ImGui::SetCursorPosY(45);
    ImGui::Separator();
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(70);
    ImGui::PushItemWidth(leftWidth - 150);
    ImGui::InputTextWithHint("##filter", "🔍 Search processes...", g_state.process_filter, sizeof(g_state.process_filter));
    ImGui::PopItemWidth();

    ImGui::SameLine();
    if (ImGui::Button("⟳", ImVec2(40, 32))) {
        g_state.processes = GetProcessList();
    }

    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(115);
    ImGui::BeginChild("ProcList", ImVec2(leftWidth - 50, windowHeight - 540), true);

    if (g_state.processes.empty())
        g_state.processes = GetProcessList();

    std::string filterLower = ToLowerAscii(g_state.process_filter);
    for (const auto& [name, pid] : g_state.processes) {
        if (filterLower.size() > 0) {
            std::string nameLower = ToLowerAscii(name);
            if (nameLower.find(filterLower) == std::string::npos)
                continue;
        }

        bool selected = (g_state.selected_pid == pid);
        if (ImGui::Selectable(std::format("{}  [{}]", name, pid).c_str(), selected)) {
            g_state.selected_pid = pid;
            g_state.selected_process = name;
        }
    }
    ImGui::EndChild();
    ImGui::EndChild();
    ImGui::EndChild();
    ImGui::SameLine(0.0f, spacing);
    ImGui::BeginChild("RightColumn", ImVec2(rightWidth, windowHeight - 160), false, ImGuiWindowFlags_NoMove);
    ImGui::BeginChild("SettingsCard", ImVec2(rightWidth - 20, 250), true);
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(15);
    ImGui::TextColored(ImColor(Colors::Accent), "INJECTION SETTINGS");
    ImGui::SetCursorPosY(45);
    ImGui::Separator();
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(75);
    const char* methods[] = { "LoadLibrary (Classic)", "Manual Mapping (Stealth)" };
    ImGui::SetCursorPosX(15);
    ImGui::Combo("##method", &g_state.injection_method, methods, IM_ARRAYSIZE(methods));
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(120);
    ImGui::Checkbox("Auto-close after injection", &g_state.auto_close);
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(155);
    ImGui::TextColored(ImColor(Colors::TextSecondary), "Method Info:");
    ImGui::SetCursorPosX(15);
    {
        ImVec4 col = ImColor(Colors::TextSecondary).Value;
        col.w *= 0.8f;
        ImGui::TextColored(col,
            g_state.injection_method == 0 ? "Standard injection, more compatible" : "Stealth injection, harder to detect");
    }
    ImGui::EndChild();
    ImGui::Spacing();
    ImGui::BeginChild("ActionCard", ImVec2(rightWidth - 20, 180), true);
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(15);
    ImGui::TextColored(ImColor(Colors::Accent), "ACTIONS");
    ImGui::SetCursorPosY(45);
    ImGui::Separator();
    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(75);
    bool canInject = (g_state.selected_pid != 0 && strlen(g_state.dll_path) > 0);

    ImVec2 btnSize(rightWidth - 50, 48);
    if (canInject) {
        ImGui::PushStyleColor(ImGuiCol_Button, Colors::Success);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(56, 214, 123, 255));
        if (ImGui::Button("🚀 INJECT NOW", btnSize)) {
            bool success = InjectDLL(g_state.selected_pid, g_state.selected_dll, g_state.injection_method);
            if (success) {
                g_state.status_message = std::format("✓ Successfully injected into {}", g_state.selected_process);
                g_state.status_type = 1;
                g_state.status_timer = 3.0f;
                if (g_state.auto_close)
                    g_state.running = false;
            }
            else {
                g_state.status_message = "✗ Injection failed: " + GetLastErrorAsString();
                g_state.status_type = 2;
                g_state.status_timer = 3.0f;
            }
        }
        ImGui::PopStyleColor(2);
    }
    else {
        ImGui::PushStyleColor(ImGuiCol_Button, Colors::CardBg);
        ImGui::PushStyleColor(ImGuiCol_Text, Colors::TextSecondary);
        ImGui::Button("⚠ SELECT DLL & PROCESS", btnSize);
        ImGui::PopStyleColor(2);
    }

    ImGui::SetCursorPosX(15);
    ImGui::SetCursorPosY(135);
    ImGui::TextColored(ImColor(Colors::TextSecondary), "Selected: %s",
        g_state.selected_pid ? std::format("{} ({})", g_state.selected_process, g_state.selected_pid).c_str() : "None");
    ImGui::EndChild();

    ImGui::EndChild();

    ImGui::SetCursorPosY(windowHeight - 55);
    ImGui::BeginChild("StatusBar", ImVec2(windowWidth - 40, 40), false);
    ImDrawList* statusDraw = ImGui::GetWindowDrawList();
    ImVec2 statusPos = ImGui::GetCursorScreenPos();
    statusDraw->AddRectFilled(statusPos, ImVec2(statusPos.x + windowWidth - 40, statusPos.y + 40),
        IM_COL32(28, 32, 37, 255), 8.0f, ImDrawFlags_RoundCornersBottom);

    if (g_state.status_timer > 0.0f) {
        g_state.status_timer -= ImGui::GetIO().DeltaTime;
        ImU32 statusColor = (g_state.status_type == 1) ? Colors::Success :
            (g_state.status_type == 2) ? Colors::Error : Colors::TextSecondary;
        ImGui::SetCursorPosX(15);
        ImGui::SetCursorPosY(10);
        ImGui::TextColored(ImColor(statusColor), "%s", g_state.status_message.c_str());
    }
    else {
        ImGui::SetCursorPosX(15);
        ImGui::SetCursorPosY(10);
        ImGui::TextColored(ImColor(Colors::TextSecondary), "Ready | Encryptic Injector v2.0");
    }

    ImGui::SameLine(windowWidth - 120);
    ImGui::SetCursorPosY(10);
    if (ImGui::Button("About", ImVec2(80, 28))) {
        MessageBoxA(g_hwnd,
            "Encryptic Injector v2.0\n\nModern DLL Injection \n\nFeatures:\n• LoadLibrary Injection\n• Manual Mapping\n• Drag & Drop Support\n• Process Filtering\n\nDeveloped by Longno",
            "About Encryptic Injector", MB_OK | MB_ICONINFORMATION);
    }

    ImGui::EndChild();

    ImGui::End();

    g_state.animation_offset += io.DeltaTime;
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
                    g_state.status_message = "✓ DLL loaded successfully";
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
        200, 100, 980, 700, nullptr, nullptr, wc.hInstance, nullptr);

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
    io.Fonts->AddFontDefault();
    ImFont* fontMedium = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 16.0f);
    if (!fontMedium) io.Fonts->AddFontDefault();

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
