#include <iostream>
#include <filesystem>
#include <windows.h>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <thread>
#include <ctime>
#include <sstream>
#include <iomanip>

#include "auth.hpp" // keyauth
#include "skStr.h" // encryption
#include "utils.hpp" // keyauth shit
#include "protect/protectmain.h" // github protection

#define JobObjectFreezeInformation 18

#define BRAND_COLOR "\x1b[38;2;128;0;128m" //Brand coloring
#define BRAND_RESET "\x1b[0m" // idk why i added ts dont remove it doe

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
void sessionStatus();

std::string tm_to_readable_time(tm ctx)
{
    char buffer[100];
    // Format: YYYY-MM-DD HH:MM:SS
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &ctx);
    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp)
{
    std::tm tm = {};
    std::istringstream ss(timestamp);
    // Adjust the format if needed.
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    return std::mktime(&tm);
}

static std::tm timet_to_tm(time_t timestamp)
{
    std::tm tm;
    // Use localtime_s for thread safety.
    localtime_s(&tm, &timestamp);
    return tm;
}

void sessionStatus()
{
    while (true)
    {
        // For now, simply sleep.
        Sleep(1000);
    }
}

using namespace KeyAuth;

// Copy and paste from https://keyauth.cc/app/ and replace these string variables
// Please watch tutorial HERE https://www.youtube.com/watch?v=5x4YkTmFH-U
std::string name = skCrypt("").decrypt(); // App name
std::string ownerid = skCrypt("").decrypt();  // Account ID
std::string version = skCrypt("").decrypt();          // Application version
std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt(); // Change if using custom domains
std::string path = skCrypt("").decrypt();                // (OPTIONAL)

api KeyAuthApp(name, ownerid, version, url, path);

typedef struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;
    ULONG LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

// Definition of JOBOBJECT_FREEZE_INFORMATION
typedef struct _JOBOBJECT_FREEZE_INFORMATION
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG FreezeOperation : 1;
            ULONG FilterOperation : 1;
            ULONG SwapOperation : 1;
            ULONG Reserved : 29;
        };
    };
    BOOLEAN Freeze;
    BOOLEAN Swap;
    UCHAR Reserved0[2];
    JOBOBJECT_WAKE_FILTER WakeFilter;
} JOBOBJECT_FREEZE_INFORMATION, * PJOBOBJECT_FREEZE_INFORMATION;

HANDLE globalJobHandle = NULL;

bool FreezeProcess(HANDLE hProcess)
{
    globalJobHandle = CreateJobObject(NULL, NULL);
    if (!globalJobHandle)
    {
        std::cerr << "Failed to create Job Object. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!AssignProcessToJobObject(globalJobHandle, hProcess))
    {
        std::cerr << "Failed to assign process to Job Object. Error: " << GetLastError() << std::endl;
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }

    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1; // Initiate freeze
    freezeInfo.Freeze = TRUE;

    if (!SetInformationJobObject(
        globalJobHandle,
        (JOBOBJECTINFOCLASS)JobObjectFreezeInformation,
        &freezeInfo,
        sizeof(freezeInfo)))
    {
        std::cerr << "Failed to freeze Job Object. Error: " << GetLastError() << std::endl;
        CloseHandle(globalJobHandle);
        globalJobHandle = NULL;
        return false;
    }

    return true;
}

bool ThawProcess(HANDLE hProcess)
{
    if (!globalJobHandle)
    {
        std::cerr << "No valid job handle available for raping. Did you freeze the process first?" << std::endl;
        return false;
    }

    JOBOBJECT_FREEZE_INFORMATION freezeInfo = { 0 };
    freezeInfo.FreezeOperation = 1; // Unfreeze operation
    freezeInfo.Freeze = FALSE;

    if (!SetInformationJobObject(
        globalJobHandle,
        (JOBOBJECTINFOCLASS)JobObjectFreezeInformation,
        &freezeInfo,
        sizeof(freezeInfo)))
    {
        std::cerr << "Failed to rape Object. Error: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "Process raped successfully!" << std::endl;
    return true;
}

DWORD GetServicePID(const wchar_t* serviceName) {
    DWORD pid = 0;

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        std::wcerr << L"Error opening Service Control Manager: " << GetLastError() << std::endl;
        return 0;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName, SERVICE_QUERY_STATUS);
    if (!hService) {
        std::wcerr << L"Error opening service: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        pid = ssp.dwProcessId;
    }
    else {
        std::wcerr << L"Error obtaining service status: " << GetLastError() << std::endl;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return pid;
}

HANDLE GetProcessHandle(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Error opening process (PID: " << processId << "): " << GetLastError() << std::endl;
    }
    return hProcess;
}

void cancel2(int pid)
{
    while (true) {
        if (GetAsyncKeyState(VK_F8) & 0x8000) {
            ThawProcess(GetProcessHandle(pid));
        }
        if (GetAsyncKeyState(VK_F9) & 0x8000) {
            FreezeProcess(GetProcessHandle(pid));
        }
        Sleep(20);
    }
}

void adjust_privileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    try {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            throw std::runtime_error("Failed to open process token.");
        }

        LUID luid;
        if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
            throw std::runtime_error("Failed to look up privilege value.");
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr)) {
            throw std::runtime_error("Failed to adjust token privileges.");
        }

    }
    catch (const std::exception& e) {
        std::wstring error_message = L"Failed to adjust privileges: " + std::wstring(e.what(), e.what() + strlen(e.what()));
    }
}

std::string RandomString(int length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int charsetSize = sizeof(charset) - 1;
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; i++) {
        result.push_back(charset[rand() % charsetSize]);
    }
    return result;
}

// Thread function to update the console title every 1 millisecond.
void updateConsoleTitle() {
    while (true) {
        std::string title = "Made by @terminated_ - " + RandomString(25);
        SetConsoleTitleA(title.c_str());
        Sleep(1);
    }
}

int main()
{
   // mainprotect(); // this is the protection shit if u need it (this is from github, i didnt make ts my self if u wanna buy good protection dm @terminated_ on discord.)
    KeyAuthApp.init();
    adjust_privileges();
    srand(static_cast<unsigned int>(time(NULL)));

    std::thread titleThread(updateConsoleTitle);
    titleThread.detach();

    // Resize the console window.
    HWND console = GetConsoleWindow();
    if (console != NULL) {
        RECT rect;
        GetWindowRect(console, &rect);
        MoveWindow(console, rect.left, rect.top, 600, 400, TRUE);
    }

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    std::string key;

    std::wcout << skCrypt(BRAND_COLOR "\n  [+] Enter License Key > ");
    std::cin >> key;
    KeyAuthApp.license(key);

    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    std::thread run(checkAuthenticated, ownerid);
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check(sessionStatus); // do NOT remove this function either.

    Beep(400, 500);
    system("sc start vgc");

    std::wcout << BRAND_COLOR << "\n  [OK] Injected to User client." << BRAND_RESET << std::endl;
    system("cls");

    std::wcout << BRAND_COLOR << "\n  [+] Waiting for VALORANT-Win64-Shipping.exe..." << BRAND_RESET << std::endl;
    Sleep(50);

    uint32_t vgc_pid = 0;

    while (vgc_pid == 0) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (wcscmp(entry.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) {
                    vgc_pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        Sleep(2000);
    }

    std::wcout << ANSI_COLOR_GREEN << "\n  [+] VALORANT-Win64-Shipping.exe found.\n\n  [+] Loading Bypass..." << ANSI_COLOR_RESET << std::endl;
    std::wcout << BRAND_COLOR << "\n  [>] ETA: 45 Seconds.." << BRAND_RESET << std::endl;

    Sleep(45000); // gives time for valorant to load do NOT delete ts it's very important u mr robot skid

    const wchar_t* serviceName = L"Dnscache";
    DWORD pid = GetServicePID(serviceName);

    if (pid) {
        FreezeProcess(GetProcessHandle(pid));

        std::wcout << ANSI_COLOR_GREEN << "\n  [>] Done!" << BRAND_RESET << std::endl;
        std::wcout << BRAND_COLOR << "\n\n  [OK] Popup has been bypassed!" << BRAND_RESET << std::endl;
        std::wcout << ANSI_COLOR_RED << "\n  [!] DO NOT CLOSE THIS WINDOW!" << ANSI_COLOR_RESET << std::endl; // yeah dont close the CMD trust me.
        std::wcout << BRAND_COLOR << "\n\n  [+] Press F2 to kill bypass safely." << ANSI_COLOR_RESET << std::endl;
        Beep(400, 300);

        while (true) {
            if (GetAsyncKeyState(VK_F2) & 0x8000) {
                std::wcout << ANSI_COLOR_YELLOW << "\n  [-] Removing bypass. Exiting..." << ANSI_COLOR_RESET << std::endl;
                ThawProcess(GetProcessHandle(pid));
                Beep(400, 200);
                std::wcout << ANSI_COLOR_GREEN << "\n  [+] Bypass removed. Exiting..." << ANSI_COLOR_RESET << std::endl;
                exit(0);
            }
            Sleep(20);
        }
    }

    return 0;
}
