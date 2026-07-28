#pragma once

#include <windows.h>
#include <string>

std::string ToLowerAscii(const std::string& s);
bool IsDllFilePath(const char* path);
std::string FormatWinError(DWORD err);
std::string GetLastErrorAsString();
bool IsCurrentProcessElevated();
