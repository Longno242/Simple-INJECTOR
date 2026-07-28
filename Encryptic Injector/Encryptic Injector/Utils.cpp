#include "Utils.h"

#include <cctype>

std::string ToLowerAscii(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s)
        out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}

bool IsDllFilePath(const char* path) {
    if (!path) return false;
    std::string p(path);
    const auto pos = p.find_last_of('.');
    if (pos == std::string::npos) return false;
    return ToLowerAscii(p.substr(pos)) == ".dll";
}

std::string FormatWinError(DWORD err) {
    if (err == 0) return "Unknown error";
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr, err, 0, (LPSTR)&buf, 0, nullptr);
    std::string msg = buf ? buf : "Unknown error";
    if (buf) LocalFree(buf);
    while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' '))
        msg.pop_back();
    return msg;
}

std::string GetLastErrorAsString() {
    return FormatWinError(GetLastError());
}

bool IsCurrentProcessElevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev{};
        DWORD size = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}
