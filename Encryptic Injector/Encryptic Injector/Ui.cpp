#include "Ui.h"

#include "AppState.h"
#include "Injection.h"
#include "Process.h"
#include "Settings.h"
#include "Utils.h"

#include <commdlg.h>
#include <algorithm>
#include <format>
#include <thread>

#include "imgui/imgui.h"

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

void PollInjectResult() {
    if (!g_state.inject_done.exchange(false)) return;
    std::lock_guard lock(g_state.inject_mutex);
    g_state.status_message = g_state.pending_status;
    g_state.status_type = g_state.pending_ok.load() ? 1 : 2;
    g_state.status_timer = 4.0f;
    if (g_state.pending_ok.load() && g_state.auto_close)
        g_state.running = false;
    SaveSettings();
}

void StartInjectJob() {
    if (g_state.injecting.load()) return;

    const DWORD pid = g_state.selected_pid;
    const std::string dll = g_state.selected_dll;
    const std::string proc = g_state.selected_process;
    const int method = g_state.injection_method;
    const bool erase = g_state.erase_pe_headers;
    const int delay = g_state.inject_delay_ms;

    if (!dll.empty() && !DllMatchesProcessArch(dll, pid)) {
        g_state.status_message = "Arch mismatch: DLL and process bitness differ";
        g_state.status_type = 2;
        g_state.status_timer = 4.0f;
        return;
    }

    g_state.injecting = true;
    g_state.inject_done = false;

    std::thread([pid, dll, proc, method, erase, delay]() {
        if (delay > 0)
            Sleep(static_cast<DWORD>(delay));

        SetLastError(0);
        const bool ok = InjectDLL(pid, dll, method, erase);
        const DWORD err = GetLastError();

        {
            std::lock_guard lock(g_state.inject_mutex);
            if (ok) {
                g_state.pending_status = std::format("Injected into {}", proc);
                g_state.pending_ok = true;
            }
            else {
                g_state.pending_status = "Failed: " + FormatWinError(err);
                g_state.pending_ok = false;
            }
        }
        g_state.inject_done = true;
        g_state.injecting = false;
    }).detach();
}

void RenderUI() {
    PollInjectResult();

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
    const float footerH = rowH + 34.0f + 52.0f + pad + 8.0f;
    const bool injecting = g_state.injecting.load();

    ImGui::SetCursorPos(ImVec2(pad, pad));
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::Text);
    ImGui::Text("Encryptic Injector");
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::SetCursorPosX(w + pad - 28);
    ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextMuted);
    ImGui::Text("v4.0");
    ImGui::PopStyleColor();

    if (!g_state.is_elevated) {
        ImGui::SetCursorPosX(pad);
        ImGui::PushStyleColor(ImGuiCol_Text, Theme::Error);
        ImGui::TextWrapped("Not elevated — run as Administrator for protected processes.");
        ImGui::PopStyleColor();
    }

    ImGui::SetCursorPosX(pad);
    ImGui::Separator();

    ImGui::SetCursorPosX(pad);
    DrawSectionLabel("DLL");
    ImGui::SetCursorPosX(pad);
    ImGui::PushItemWidth(w - 76);
    ImGui::InputTextWithHint("##dll", "Select a .dll file...", g_state.dll_path,
        IM_ARRAYSIZE(g_state.dll_path), ImGuiInputTextFlags_ReadOnly);
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (FlatButton("Browse##dll", ImVec2(68, ImGui::GetFrameHeight()), !injecting)) {
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
            SaveSettings();
        }
    }

    ImGui::SetCursorPosX(pad);
    DrawSectionLabel("Process");
    ImGui::SetCursorPosX(pad);
    ImGui::PushItemWidth(w - 56);
    ImGui::BeginDisabled(injecting);
    ImGui::InputTextWithHint("##filter", "Filter...", g_state.process_filter, sizeof(g_state.process_filter));
    ImGui::EndDisabled();
    ImGui::PopItemWidth();
    ImGui::SameLine();
    if (FlatButton("Refresh", ImVec2(48, ImGui::GetFrameHeight()), !injecting))
        g_state.processes = GetProcessList();

    const bool dllKnown = !g_state.selected_dll.empty();
    const bool dll64 = dllKnown && IsDll64Bit(g_state.selected_dll);

    ImGui::SetCursorPosX(pad);
    ImGui::BeginChild("##proclist", ImVec2(w, (std::max)(100.0f, display.y - ImGui::GetCursorPosY() - footerH - (g_state.is_elevated ? 118.0f : 138.0f))), true);
    if (g_state.processes.empty()) g_state.processes = GetProcessList();

    std::string filterLower = ToLowerAscii(g_state.process_filter);
    for (const auto& proc : g_state.processes) {
        if (g_state.match_arch_only && dllKnown && proc.is64 != dll64)
            continue;
        if (!filterLower.empty()) {
            std::string nameLower = ToLowerAscii(proc.name);
            std::string pidStr = std::to_string(proc.pid);
            if (nameLower.find(filterLower) == std::string::npos && pidStr.find(filterLower) == std::string::npos)
                continue;
        }
        bool selected = (g_state.selected_pid == proc.pid);
        ImGui::PushStyleColor(ImGuiCol_Header, Theme::SurfaceHi);
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, Theme::SurfaceHi);
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, Theme::SurfaceHi);
        if (ImGui::Selectable(std::format("{}  ({})  [{}]", proc.name, proc.pid, proc.is64 ? "x64" : "x86").c_str(), selected) && !injecting) {
            g_state.selected_pid = proc.pid;
            g_state.selected_process = proc.name;
        }
        ImGui::PopStyleColor(3);
    }
    ImGui::EndChild();

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
    ImGui::BeginDisabled(injecting);
    ImGui::PushItemWidth(w);
    if (ImGui::Combo("##method", &g_state.injection_method, methods, IM_ARRAYSIZE(methods)))
        SaveSettings();
    ImGui::PopItemWidth();

    ImGui::SetCursorPosX(pad);
    if (ImGui::Checkbox("Auto-close on success", &g_state.auto_close))
        SaveSettings();
    ImGui::SameLine(0, 24);
    if (g_state.injection_method == 1) {
        if (ImGui::Checkbox("Erase PE headers", &g_state.erase_pe_headers))
            SaveSettings();
    }
    else {
        ImGui::BeginDisabled();
        bool dummy = g_state.erase_pe_headers;
        ImGui::Checkbox("Erase PE headers", &dummy);
        ImGui::EndDisabled();
    }

    ImGui::SetCursorPosX(pad);
    if (ImGui::Checkbox("Match DLL arch", &g_state.match_arch_only))
        SaveSettings();
    ImGui::SameLine(0, 24);
    ImGui::SetNextItemWidth(90.0f);
    if (ImGui::InputInt("Delay ms", &g_state.inject_delay_ms, 50, 250)) {
        if (g_state.inject_delay_ms < 0) g_state.inject_delay_ms = 0;
        SaveSettings();
    }
    ImGui::EndDisabled();

    ImGui::SetCursorPosX(pad);
    ImGui::Separator();

    bool canInject = g_state.selected_pid != 0 && strlen(g_state.dll_path) > 0 && !injecting;
    ImGui::SetCursorPosX(pad);
    if (injecting) {
        ImGui::PushStyleColor(ImGuiCol_Button, Theme::Surface);
        ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextDim);
        ImGui::Button("Injecting...", ImVec2(w, 34));
        ImGui::PopStyleColor(2);
    }
    else if (FlatButton(canInject ? "Inject" : "Select DLL and process", ImVec2(w, 34), canInject)) {
        StartInjectJob();
    }

    ImGui::SetCursorPosX(pad);
    if (g_state.status_timer > 0.0f) {
        g_state.status_timer -= io.DeltaTime;
        ImU32 col = (g_state.status_type == 1) ? Theme::Success : Theme::Error;
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextWrapped("%s", g_state.status_message.c_str());
        ImGui::PopStyleColor();
    }
    else if (injecting) {
        ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextDim);
        ImGui::TextUnformatted("Injecting in background...");
        ImGui::PopStyleColor();
    }
    else {
        ImGui::PushStyleColor(ImGuiCol_Text, Theme::TextMuted);
        ImGui::TextUnformatted(g_state.is_elevated ? "Ready" : "Ready (limited privileges)");
        ImGui::PopStyleColor();
    }

    ImGui::End();
}
