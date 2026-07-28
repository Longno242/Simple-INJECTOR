#include "Settings.h"

#include "AppState.h"
#include "Utils.h"

#include <algorithm>
#include <fstream>
#include <string>

static std::string GetSettingsPath() {
    char modulePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
    std::string path(modulePath);
    const size_t slash = path.find_last_of("\\/");
    if (slash != std::string::npos)
        path.resize(slash + 1);
    else
        path.clear();
    return path + "injector_settings.ini";
}

void LoadSettings() {
    std::ifstream in(GetSettingsPath());
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        const std::string val = line.substr(eq + 1);
        if (key == "Method") g_state.injection_method = std::clamp(std::atoi(val.c_str()), 0, 6);
        else if (key == "CloseOnInject") g_state.auto_close = std::atoi(val.c_str()) != 0;
        else if (key == "EraseHeaders") g_state.erase_pe_headers = std::atoi(val.c_str()) != 0;
        else if (key == "Delay") {
            const int delay = std::atoi(val.c_str());
            g_state.inject_delay_ms = delay < 0 ? 0 : delay;
        }
        else if (key == "MatchArch") g_state.match_arch_only = std::atoi(val.c_str()) != 0;
        else if (key == "DllPath" && !val.empty() && IsDllFilePath(val.c_str())) {
            strcpy_s(g_state.dll_path, val.c_str());
            g_state.selected_dll = val;
        }
    }
}

void SaveSettings() {
    std::ofstream out(GetSettingsPath(), std::ios::trunc);
    if (!out) return;
    out << "Method=" << g_state.injection_method << "\n";
    out << "AutoInject=0\n";
    out << "CloseOnInject=" << (g_state.auto_close ? 1 : 0) << "\n";
    out << "EraseHeaders=" << (g_state.erase_pe_headers ? 1 : 0) << "\n";
    out << "HideModule=0\n";
    out << "Delay=" << g_state.inject_delay_ms << "\n";
    out << "MatchArch=" << (g_state.match_arch_only ? 1 : 0) << "\n";
    out << "DllPath=" << g_state.selected_dll << "\n";
}
