#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/backends/imgui_impl_win32.h"
#include "imgui/backends/imgui_impl_dx11.h"
#include <d3d11.h>
#define DIRECTINPUT_VERSION 0x0800
#include <dinput.h>

#ifdef _CONSOLE
int main() {
    return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOWDEFAULT);
}
#endif

#pragma comment(lib, "d3d11.lib")

HWND g_hwnd = nullptr;
ID3D11Device* g_pd3dDevice = nullptr;
ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
IDXGISwapChain* g_pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

struct AppState {
    bool running = true;
    bool show_success = false;
    bool show_error = false;
    float success_alpha = 0.0f;
    float error_alpha = 0.0f;
    std::string status_message;
    std::string selected_dll;
    std::string selected_process;
    DWORD selected_pid = 0;
    std::vector<std::pair<std::string, DWORD>> processes;
    char dll_path[512] = "";
    char process_filter[256] = "";
    bool inject_on_select = false;
    bool auto_close = false;
    int injection_method = 0;
    float animation_time = 0.0f;
};

static AppState g_state;

namespace Colors {
    constexpr ImU32 Background = IM_COL32(10, 10, 12, 255);
    constexpr ImU32 BackgroundLight = IM_COL32(18, 18, 22, 255);
    constexpr ImU32 Surface = IM_COL32(28, 28, 35, 255);
    constexpr ImU32 SurfaceHover = IM_COL32(35, 35, 45, 255);
    constexpr ImU32 SurfaceActive = IM_COL32(45, 45, 60, 255);
    constexpr ImU32 Border = IM_COL32(50, 50, 65, 255);
    constexpr ImU32 BorderActive = IM_COL32(80, 80, 100, 255);
    constexpr ImU32 Accent = IM_COL32(136, 86, 255, 255);
    constexpr ImU32 AccentHover = IM_COL32(160, 120, 255, 255);
    constexpr ImU32 AccentActive = IM_COL32(120, 70, 230, 255);
    constexpr ImU32 TextPrimary = IM_COL32(255, 255, 255, 255);
    constexpr ImU32 TextSecondary = IM_COL32(180, 180, 190, 255);
    constexpr ImU32 TextMuted = IM_COL32(120, 120, 130, 255);
    constexpr ImU32 Success = IM_COL32(50, 220, 120, 255);
    constexpr ImU32 Error = IM_COL32(255, 80, 80, 255);
    constexpr ImU32 Warning = IM_COL32(255, 180, 60, 255);
}

std::string GetLastErrorAsString() {
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) return std::string();

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}

std::vector<std::pair<std::string, DWORD>> GetProcessList() {
    std::vector<std::pair<std::string, DWORD>> processes;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return processes;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &pe)) {
        do {
            std::string name = pe.szExeFile;
            if (name != "svchost.exe" && name != "csrss.exe" && name != "smss.exe" && name != "services.exe" && name != "lsass.exe" && name != "winlogon.exe") { processes.push_back({ name, pe.th32ProcessID });
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);

    std::sort(processes.begin(), processes.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });

    return processes;
}

bool InjectDLL(DWORD pid, const std::string& dllPath, int method) {
    if (method == 0) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) return false;

        LPVOID allocMem = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!allocMem) {
            CloseHandle(hProcess);
            return false;
        }

        if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(),
            dllPath.size() + 1, NULL)) {
            VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(
            hKernel32, "LoadLibraryA");

        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr,
            allocMem, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }
    return false;
}

void SetupImGuiStyle() {
    ImGuiStyle& style = ImGui::GetStyle();
    ImVec4* colors = style.Colors;

    colors[ImGuiCol_WindowBg] = ImColor(Colors::Background);
    colors[ImGuiCol_ChildBg] = ImColor(Colors::Surface);
    colors[ImGuiCol_PopupBg] = ImColor(Colors::Surface);
    colors[ImGuiCol_Border] = ImColor(Colors::Border);
    colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_Text] = ImColor(Colors::TextPrimary);
    colors[ImGuiCol_TextDisabled] = ImColor(Colors::TextMuted);
    colors[ImGuiCol_TextSelectedBg] = ImColor(Colors::Accent);
    colors[ImGuiCol_Button] = ImColor(Colors::Surface);
    colors[ImGuiCol_ButtonHovered] = ImColor(Colors::Accent);
    colors[ImGuiCol_ButtonActive] = ImColor(Colors::AccentActive);
    colors[ImGuiCol_Header] = ImColor(Colors::Surface);
    colors[ImGuiCol_HeaderHovered] = ImColor(Colors::SurfaceHover);
    colors[ImGuiCol_HeaderActive] = ImColor(Colors::Accent);
    colors[ImGuiCol_FrameBg] = ImColor(Colors::BackgroundLight);
    colors[ImGuiCol_FrameBgHovered] = ImColor(Colors::Surface);
    colors[ImGuiCol_FrameBgActive] = ImColor(Colors::SurfaceHover);
    colors[ImGuiCol_CheckMark] = ImColor(Colors::Accent);
    colors[ImGuiCol_SliderGrab] = ImColor(Colors::Accent);
    colors[ImGuiCol_SliderGrabActive] = ImColor(Colors::AccentActive);
    colors[ImGuiCol_ScrollbarBg] = ImColor(Colors::Background);
    colors[ImGuiCol_ScrollbarGrab] = ImColor(Colors::SurfaceHover);
    colors[ImGuiCol_ScrollbarGrabHovered] = ImColor(Colors::Accent);
    colors[ImGuiCol_ScrollbarGrabActive] = ImColor(Colors::AccentActive);
    colors[ImGuiCol_Separator] = ImColor(Colors::Border);
    colors[ImGuiCol_SeparatorHovered] = ImColor(Colors::Accent);
    colors[ImGuiCol_SeparatorActive] = ImColor(Colors::Accent);
    colors[ImGuiCol_ResizeGrip] = ImColor(Colors::Border);
    colors[ImGuiCol_ResizeGripHovered] = ImColor(Colors::Accent);
    colors[ImGuiCol_ResizeGripActive] = ImColor(Colors::AccentActive);
    colors[ImGuiCol_TitleBg] = ImColor(Colors::Background);
    colors[ImGuiCol_TitleBgActive] = ImColor(Colors::Surface);
    colors[ImGuiCol_TitleBgCollapsed] = ImColor(Colors::Background);
    colors[ImGuiCol_PlotLines] = ImColor(Colors::Accent);
    colors[ImGuiCol_PlotLinesHovered] = ImColor(Colors::AccentHover);
    colors[ImGuiCol_PlotHistogram] = ImColor(Colors::Accent);
    colors[ImGuiCol_PlotHistogramHovered] = ImColor(Colors::AccentHover);

    style.WindowRounding = 8.0f;
    style.ChildRounding = 6.0f;
    style.FrameRounding = 4.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.WindowPadding = ImVec2(12, 12);
    style.FramePadding = ImVec2(10, 6);
    style.ItemSpacing = ImVec2(8, 6);
    style.ItemInnerSpacing = ImVec2(6, 4);
    style.GrabMinSize = 12.0f;
    style.ScrollbarSize = 10.0f;
}

void GlowButton(const char* label, const ImVec2& size_arg = ImVec2(0, 0),
    ImU32 glow_color = Colors::Accent) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImGui::CalcItemSize(size_arg,
        label_size.x + style.FramePadding.x * 2.0f,
        label_size.y + style.FramePadding.y * 2.0f);

    const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
    ImGui::ItemSize(size, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, id)) return;

    bool hovered, held;
    bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);

    if (hovered || held) {
        float glow_intensity = held ? 1.0f : 0.6f;
        for (int i = 3; i > 0; i--) {
            float alpha = (0.3f - i * 0.08f) * glow_intensity;
            window->DrawList->AddRect(
                ImVec2(bb.Min.x - i, bb.Min.y - i),
                ImVec2(bb.Max.x + i, bb.Max.y + i),
                ImColor(ImColor(glow_color).Value.x, ImColor(glow_color).Value.y,
                    ImColor(glow_color).Value.z, alpha),
                style.FrameRounding + i, 0, 2.0f
            );
        }
    }

    ImU32 col = held ? Colors::AccentActive : (hovered ? Colors::Accent : Colors::Surface);
    ImGui::RenderFrame(bb.Min, bb.Max, col, true, style.FrameRounding);

    ImVec2 text_pos = ImVec2(
        bb.Min.x + (size.x - label_size.x) * 0.5f,
        bb.Min.y + (size.y - label_size.y) * 0.5f
    );
    window->DrawList->AddText(text_pos, Colors::TextPrimary, label);

    if (pressed) g_state.animation_time = 0.0f;
}

void ModernCheckbox(const char* label, bool* v) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);

    const float square_sz = ImGui::GetFrameHeight();
    const ImVec2 pos = window->DC.CursorPos;
    const ImRect total_bb(pos, ImVec2(pos.x + square_sz + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f),
        pos.y + label_size.y + style.FramePadding.y * 2.0f));
    const ImRect check_bb(pos, ImVec2(pos.x + square_sz, pos.y + square_sz));

    ImGui::ItemSize(total_bb, style.FramePadding.y);
    if (!ImGui::ItemAdd(total_bb, id)) return;

    bool hovered, held;
    bool pressed = ImGui::ButtonBehavior(total_bb, id, &hovered, &held);
    if (pressed) {
        *v = !(*v);
        ImGui::MarkItemEdited(id);
    }

    const ImU32 col = ImGui::GetColorU32((held && hovered) ? ImGuiCol_FrameBgActive : hovered ? ImGuiCol_FrameBgHovered : ImGuiCol_FrameBg);
    ImGui::RenderFrame(check_bb.Min, check_bb.Max, col, true, style.FrameRounding);

    if (*v) {
        const float pad = (std::max)(1.0f, std::floor(square_sz / 6.0f));
        const float thickness = (std::max)(2.0f, square_sz / 5.0f);

        float anim = sinf(g_state.animation_time * 10.0f) * 0.5f + 0.5f;
        ImU32 check_col = ImColor(Colors::Accent);

        ImVec2 points[3] = {
            ImVec2(check_bb.Min.x + pad, check_bb.Min.y + square_sz / 2.0f),
            ImVec2(check_bb.Min.x + square_sz / 2.0f, check_bb.Max.y - pad),
            ImVec2(check_bb.Max.x - pad, check_bb.Min.y + pad)
        };

        window->DrawList->AddPolyline(points, 3, check_col, false, thickness);
    }

    if (label_size.x > 0.0f) {
        ImGui::RenderText(ImVec2(check_bb.Max.x + style.ItemInnerSpacing.x,
            check_bb.Min.y + style.FramePadding.y), label);
    }
}

void RenderUI() {
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 display_size = io.DisplaySize;

    ImDrawList* bg_draw = ImGui::GetBackgroundDrawList();
    ImU32 col_top = IM_COL32(15, 15, 18, 255);
    ImU32 col_bottom = IM_COL32(8, 8, 10, 255);
    bg_draw->AddRectFilledMultiColor(ImVec2(0, 0), display_size, col_top, col_top, col_bottom, col_bottom);

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(display_size);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);

    ImGui::Begin("Injector", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 window_pos = ImGui::GetWindowPos();
    ImVec2 window_size = ImGui::GetWindowSize();

    draw_list->AddRectFilled(
        ImVec2(window_pos.x, window_pos.y),
        ImVec2(window_pos.x + window_size.x, window_pos.y + 60),
        IM_COL32(20, 20, 25, 255), 8.0f, ImDrawFlags_RoundCornersTop
    );

    draw_list->AddRectFilled(
        ImVec2(window_pos.x + 20, window_pos.y + 58),
        ImVec2(window_pos.x + window_size.x - 20, window_pos.y + 60),
        Colors::Accent
    );

    ImGui::SetCursorPos(ImVec2(25, 18));
    ImGui::PushFont(io.Fonts->Fonts[0]);
    ImGui::TextColored(ImColor(Colors::TextPrimary), "INJECTOR");
    ImGui::PopFont();

    ImGui::SameLine();
    ImGui::SetCursorPosX(window_size.x - 100);
    ImGui::TextColored(ImColor(Colors::TextMuted), "v2.0");

    ImGui::SetCursorPosY(75);

    float content_width = window_size.x - 40;

    ImGui::PushStyleColor(ImGuiCol_ChildBg, Colors::Surface);
    ImGui::BeginChild("DLLSection", ImVec2(content_width, 100), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPos(ImVec2(15, 15));
    ImGui::TextColored(ImColor(Colors::Accent), "DLL FILE");
    ImGui::Spacing();
    ImGui::SetCursorPosX(15);
    ImGui::PushItemWidth(content_width - 150);
    ImGui::InputText("##dllpath", g_state.dll_path, IM_ARRAYSIZE(g_state.dll_path), ImGuiInputTextFlags_ReadOnly);
    ImGui::PopItemWidth();

    ImGui::SameLine();
    if (ImGui::Button("Browse", ImVec2(100, 0))) {
        OPENFILENAMEA ofn;
        CHAR szFile[512] = { 0 };
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hwnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "DLL Files\0*.dll\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

        if (GetOpenFileNameA(&ofn)) {
            strcpy_s(g_state.dll_path, szFile);
            g_state.selected_dll = szFile;
        }
    }

    if (!g_state.selected_dll.empty()) {
        ImGui::SetCursorPosX(15);
        ImGui::TextColored(ImColor(Colors::TextSecondary), "Selected: ");
        ImGui::SameLine();
        std::string filename = g_state.selected_dll.substr(g_state.selected_dll.find_last_of("\\") + 1);
        ImGui::TextColored(ImColor(Colors::Success), "%s", filename.c_str());
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, Colors::Surface);
    ImGui::BeginChild("ProcessSection", ImVec2(content_width, 280), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPos(ImVec2(15, 15));
    ImGui::TextColored(ImColor(Colors::Accent), "TARGET PROCESS");
    ImGui::Spacing();
    ImGui::SetCursorPosX(15);
    ImGui::PushItemWidth(content_width - 130);
    if (ImGui::InputTextWithHint("##filter", "Filter processes...",
        g_state.process_filter, IM_ARRAYSIZE(g_state.process_filter))) {
    }
    ImGui::PopItemWidth();

    ImGui::SameLine();
    if (ImGui::Button("Refresh", ImVec2(100, 0))) {
        g_state.processes = GetProcessList();
    }
    ImGui::Spacing();
    ImGui::SetCursorPosX(15);
    ImGui::BeginChild("ProcessList", ImVec2(content_width - 30, 180), true);

    if (g_state.processes.empty()) {
        g_state.processes = GetProcessList();
    }

    for (const auto& proc : g_state.processes) {
        if (g_state.process_filter[0] != '\0') {
            if (proc.first.find(g_state.process_filter) == std::string::npos) continue;
        }

        bool is_selected = (g_state.selected_pid == proc.second);
        ImGui::PushStyleColor(ImGuiCol_Header, is_selected ? Colors::Accent : Colors::Surface);
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, Colors::SurfaceHover);
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, Colors::Accent);

        std::string label = proc.first + " [" + std::to_string(proc.second) + "]";
        if (ImGui::Selectable(label.c_str(), is_selected)) {
            g_state.selected_pid = proc.second;
            g_state.selected_process = proc.first;
        }

        ImGui::PopStyleColor(3);
    }

    ImGui::EndChild();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, Colors::Surface);
    ImGui::BeginChild("SettingsSection", ImVec2(content_width, 100), true, ImGuiWindowFlags_NoScrollbar);

    ImGui::SetCursorPos(ImVec2(15, 15));
    ImGui::TextColored(ImColor(Colors::Accent), "SETTINGS");
    ImGui::Spacing();

    ImGui::SetCursorPosX(15);
    ModernCheckbox("Auto-inject on selection", &g_state.inject_on_select);

    ImGui::SameLine();
    ImGui::SetCursorPosX(content_width / 2);
    ModernCheckbox("Auto-close after inject", &g_state.auto_close);

    ImGui::SetCursorPosX(15);
    ImGui::Text("Method:");
    ImGui::SameLine();
    const char* methods[] = { "LoadLibrary", "Manual Map" };
    ImGui::PushItemWidth(150);
    ImGui::Combo("##method", &g_state.injection_method, methods, IM_ARRAYSIZE(methods));
    ImGui::PopItemWidth();

    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::Spacing();

    ImVec2 btn_size(content_width, 50);
    ImGui::SetCursorPosX(20);

    bool can_inject = (g_state.selected_pid != 0 && strlen(g_state.dll_path) > 0);

    if (can_inject) {
        GlowButton("INJECT", btn_size, Colors::Accent);
        if (ImGui::IsItemClicked()) {
            if (InjectDLL(g_state.selected_pid, g_state.dll_path, g_state.injection_method)) {
                g_state.show_success = true;
                g_state.success_alpha = 1.0f;
                g_state.status_message = "Successfully injected into " + g_state.selected_process;
                if (g_state.auto_close) {
                    std::thread([]() {
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        g_state.running = false;
                        }).detach();
                }
            }
            else {
                g_state.show_error = true;
                g_state.error_alpha = 1.0f;
                g_state.status_message = "Injection failed: " + GetLastErrorAsString();
            }
        }
    }
    else {
        ImGui::PushStyleColor(ImGuiCol_Button, Colors::Surface);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Colors::Surface);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, Colors::Surface);
        ImGui::Button("SELECT PROCESS AND DLL", btn_size);
        ImGui::PopStyleColor(3);
    }

    ImVec2 center(window_pos.x + window_size.x / 2, window_pos.y + window_size.y - 60);

    if (g_state.show_success && g_state.success_alpha > 0.01f) {
        ImVec2 text_size = ImGui::CalcTextSize(g_state.status_message.c_str());
        ImVec2 notif_pos(center.x - text_size.x / 2 - 15, center.y - 10);
        ImVec2 notif_size(text_size.x + 30, 40);

        draw_list->AddRectFilled(notif_pos,
            ImVec2(notif_pos.x + notif_size.x, notif_pos.y + notif_size.y),
            ImColor(50, 220, 120, (int)(g_state.success_alpha * 255)),
            6.0f);
        draw_list->AddText(
            ImVec2(notif_pos.x + 15, notif_pos.y + 10),
            IM_COL32(255, 255, 255, (int)(g_state.success_alpha * 255)),
            g_state.status_message.c_str()
        );

        g_state.success_alpha -= 0.02f;
        if (g_state.success_alpha <= 0) g_state.show_success = false;
    }

    if (g_state.show_error && g_state.error_alpha > 0.01f) {
        ImVec2 text_size = ImGui::CalcTextSize(g_state.status_message.c_str());
        ImVec2 notif_pos(center.x - text_size.x / 2 - 15, center.y - 10);
        ImVec2 notif_size(text_size.x + 30, 40);

        draw_list->AddRectFilled(notif_pos,
            ImVec2(notif_pos.x + notif_size.x, notif_pos.y + notif_size.y),
            ImColor(255, 80, 80, (int)(g_state.error_alpha * 255)),
            6.0f);
        draw_list->AddText(
            ImVec2(notif_pos.x + 15, notif_pos.y + 10),
            IM_COL32(255, 255, 255, (int)(g_state.error_alpha * 255)),
            g_state.status_message.c_str()
        );

        g_state.error_alpha -= 0.02f;
        if (g_state.error_alpha <= 0) g_state.show_error = false;
    }

    ImGui::SetCursorPosY(window_size.y - 25);
    ImGui::Separator();
    ImGui::TextColored(ImColor(Colors::TextMuted), "Ready");

    if (g_state.selected_pid != 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImColor(Colors::TextSecondary), "| Target: ");
        ImGui::SameLine();
        ImGui::TextColored(ImColor(Colors::Accent), "%s (PID: %d)",
            g_state.selected_process.c_str(), g_state.selected_pid);
    }

    ImGui::End();
    ImGui::PopStyleVar();

    g_state.animation_time += io.DeltaTime;
}

void CreateRenderTarget();
void CleanupRenderTarget();

bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
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

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };

    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam),
                DXGI_FORMAT_UNKNOWN, 0);
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
                      GetModuleHandle(NULL), NULL, NULL, NULL, NULL, TEXT("Injector"), NULL };
    RegisterClassEx(&wc);

    g_hwnd = CreateWindow(wc.lpszClassName, TEXT("Modern Injector"),
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        100, 100, 500, 700, NULL, NULL, wc.hInstance, NULL);

    if (!CreateDeviceD3D(g_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    SetupImGuiStyle();

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    while (g_state.running && msg.message != WM_QUIT) {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderUI();

        ImGui::Render();
        const float clear_color[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
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