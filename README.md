# Encryptic Injector

A small Windows DLL injector with a simple ImGui interface. The release is a single portable `.exe` — no extra files needed.

## Download

**[Latest release (v3)](https://github.com/Longno242/Simple-INJECTOR/releases/latest)** — download `Encryptic Injector.exe` and run it.

## Features

- Process list with search
- Drag & drop DLL support
- 7 injection methods:
  - LoadLibrary (Standard)
  - Manual Map (Stealth)
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
