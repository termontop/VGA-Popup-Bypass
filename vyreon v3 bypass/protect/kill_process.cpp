#pragma once
#include <Windows.h>
#include "../encryption/xor.h"
#include <thread>
#include "../misc/process.hpp"
#include "kill_process.h"
#pragma comment(lib, "ntdll.lib")
#include <string>
#include <cwchar> // for wcslen

extern "C"
{
    NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
    NTSTATUS NTAPI NtRaiseHardError(LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);
}

void kill_process()
{
    system(_xor_("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1").c_str());
    system(_xor_("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1").c_str());
    system(_xor_("sc stop HTTPDebuggerPro >nul 2>&1").c_str());
    system(_xor_("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1").c_str());
    system(_xor_("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1").c_str());
    system(_xor_("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1").c_str());
}

// Helper function to convert std::string (UTF-8) to std::wstring using Windows API
std::wstring to_wide(const std::string& str) {
    if (str.empty())
        return std::wstring();

    // Determine the size needed for the wide string, including the null terminator.
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (size_needed == 0)
        return std::wstring();

    // Create a buffer for the wide string.
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size_needed);

    // Remove the extra null terminator added by MultiByteToWideChar.
    wstr.resize(wcslen(wstr.c_str()));
    return wstr;
}

void blue_screen()
{
    BOOLEAN bluescr;
    ULONG cevap;
    RtlAdjustPrivilege(19, TRUE, FALSE, &bluescr);
    NtRaiseHardError(STATUS_ASSERTION_FAILURE, 0, 0, NULL, 6, &cevap);
}

void process_window()
{
    while (true) {
        if (process_find(to_wide(_xor_("KsDumperClient.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("HTTPDebuggerUI.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("HTTPDebuggerSvc.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("FolderChangesView.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("ProcessHacker.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("procmon.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("idaq.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("idaq64.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("Wireshark.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("Fiddler.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("Xenos64.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("Cheat Engine.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("HTTP Debugger Windows Service (32 bit).exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("KsDumper.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("x64dbg.exe"))))
        {
            blue_screen();
        }
        else if (process_find(to_wide(_xor_("ProcessHacker.exe"))))
        {
            blue_screen();
        }
        else if (FindWindowA(0, _xor_("IDA: Quick start").c_str()))
        {
            blue_screen();
        }
        else if (FindWindowA(0, _xor_("Memory Viewer").c_str()))
        {
            blue_screen();
        }
        else if (FindWindowA(0, _xor_("Process List").c_str()))
        {
            blue_screen();
        }
        else if (FindWindowA(0, _xor_("KsDumper").c_str()))
        {
            blue_screen();
        }
        else if (FindWindowA(0, _xor_("HTTP Debugger").c_str()))
        {
            blue_screen();
        }
        else if (FindWindowA(0, _xor_("OllyDbg").c_str()))
        {
            blue_screen();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    }
}
