# Encryptic Injector

A small Windows DLL injector with a simple ImGui interface. The release is a single portable `.exe` — no extra files needed.

## Download

**[Latest release (v4)](https://github.com/Longno242/Simple-INJECTOR/releases/latest)** — download `Encryptic Injector.exe` and run it.

## Features

- Process list with search and x64/x86 labels
- Drag & drop DLL support
- Async inject (UI stays responsive)
- Settings persistence (`injector_settings.ini`)
- Arch mismatch checks + optional match-arch filter
- Admin elevation banner
- 7 injection methods:
  - LoadLibrary (Standard)
  - Manual Map (with TLS, section protections, custom remote stub)
  - NtCreateThreadEx
  - QueueUserAPC
  - RtlCreateUserThread
  - LoadLibraryW
  - Thread Hijack

## Requirements

- Windows 10/11
- Visual Studio 2022 (C++20)
- x64 build recommended

## Build

1. Open `Encryptic Injector/Encryptic Injector.slnx` in Visual Studio
2. Set configuration to **Release | x64**
3. Build the solution

Output: `Encryptic Injector/x64/Release/Encryptic Injector.exe`

## Usage

1. Run as Administrator if injecting into protected processes
2. Select a `.dll` file
3. Pick a target process
4. Choose an injection method
5. Click **Inject**

## Disclaimer

For educational and authorized use only. Do not use on software or systems you do not own or have permission to test.

## License

MIT
