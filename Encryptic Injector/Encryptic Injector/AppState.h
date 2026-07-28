#pragma once

#include <windows.h>
#include <d3d11.h>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>
#include "imgui/imgui.h"

struct ProcessInfo {
    std::string name;
    DWORD pid = 0;
    bool is64 = true;
};

struct AppState {
    bool running = true;
    char dll_path[512] = "";
    std::string selected_dll;
    std::string selected_process;
    DWORD selected_pid = 0;
    std::vector<ProcessInfo> processes;
    char process_filter[256] = "";
    bool auto_close = false;
    int injection_method = 0;
    bool erase_pe_headers = true;
    int inject_delay_ms = 0;
    bool match_arch_only = true;
    bool is_elevated = false;
    std::string status_message;
    float status_timer = 0.0f;
    int status_type = 0;
    std::atomic<bool> injecting{ false };
    std::atomic<bool> inject_done{ false };
    std::atomic<bool> pending_ok{ false };
    std::string pending_status;
    std::mutex inject_mutex;
};

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

extern AppState g_state;
extern HWND g_hwnd;
extern ID3D11Device* g_pd3dDevice;
extern ID3D11DeviceContext* g_pd3dDeviceContext;
extern IDXGISwapChain* g_pSwapChain;
extern ID3D11RenderTargetView* g_mainRenderTargetView;
