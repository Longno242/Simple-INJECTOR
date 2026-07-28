#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "AppState.h"

std::vector<ProcessInfo> GetProcessList();
bool IsProcess64Bit(DWORD pid);
WORD GetPeMachine(const std::string& path);
bool IsDll64Bit(const std::string& path);
bool DllMatchesProcessArch(const std::string& dllPath, DWORD pid);
