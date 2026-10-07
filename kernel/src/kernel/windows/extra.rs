//! Imports Midnight Commander and its CRT need beyond the small replacement
//! DLLs. Missing exports become `int 0x83` trampolines; these calls implement
//! them. The text console is a character buffer painted into a Win32 window.

mod system;

use super::{
    arg, c_string, copy_ascii, fail, full_windows_path, guest_windows_path, w_string, windows_path, Window,
    WindowsState, ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
    INVALID_HANDLE_VALUE,
};
use crate::Regs;
use crate::kernel::thread;
use alloc::{vec, vec::Vec};

pub(super) struct Spec {
    pub module: &'static [u8],
    pub name: &'static [u8],
    pub arg_bytes: u32,
}

pub(super) struct Bound {
    pub name: &'static [u8],
    pub address: u32,
    pub arg_bytes: u32,
}

pub(super) struct Block {
    addr: u32,
    size: u32,
    used: bool,
}

pub(super) struct Find {
    handle: u32,
    entries: Vec<Entry>,
    index: usize,
    wide: bool,
}

struct Entry {
    name: Vec<u8>,
    short: Vec<u8>,
    size: u32,
    mtime: u32,
    dir: bool,
}

pub(super) struct Mapping {
    handle: u32,
    name: Vec<u8>,
    address: u32,
    size: u32,
}

struct Key {
    down: bool,
    ascii: u8,
    scan: u16,
    vk: u16,
    control: u32,
}

pub(super) struct Console {
    pub cols: u16,
    pub rows: u16,
    cursor_x: u16,
    cursor_y: u16,
    attr: u16,
    cells: Vec<u8>,
    input: Vec<Key>,
    keys: [u8; 256],
    extended: bool,
    pub hwnd: u32,
    /// `ReadConsoleInput` found no key. The call stays at the `int 0x83` so
    /// the next entry sees a real event instead of an empty record.
    hold: bool,
}

impl Console {
    pub(super) fn new() -> Self {
        let mut console = Self {
            cols: 80,
            rows: 25,
            cursor_x: 0,
            cursor_y: 0,
            attr: 0x07,
            cells: Vec::new(),
            input: Vec::new(),
            keys: [0; 256],
            extended: false,
            hwnd: 0,
            hold: false,
        };
        console.blank();
        console
    }

    fn blank(&mut self) {
        self.cells.clear();
        self.cells
            .resize(self.cols as usize * self.rows as usize * 2, 0);
        for cell in self.cells.chunks_exact_mut(2) {
            cell[0] = b' ';
            cell[1] = self.attr as u8;
        }
    }

}

const SPECS: &[Spec] = &[
    spec(b"ADVAPI32", b"AdjustTokenPrivileges", 24),
    spec(b"ADVAPI32", b"CheckTokenMembership", 12),
    spec(b"ADVAPI32", b"CloseServiceHandle", 4),
    spec(b"ADVAPI32", b"ControlService", 12),
    spec(b"ADVAPI32", b"DecryptFileA", 8),
    spec(b"ADVAPI32", b"EncryptFileA", 4),
    spec(b"ADVAPI32", b"EnumServicesStatusExA", 40),
    spec(b"ADVAPI32", b"FileEncryptionStatusA", 8),
    spec(b"ADVAPI32", b"GetFileSecurityA", 20),
    spec(b"ADVAPI32", b"SetFileSecurityA", 12),
    spec(b"ADVAPI32", b"SetFileSecurityW", 12),
    spec(b"ADVAPI32", b"GetSecurityDescriptorOwner", 12),
    spec(b"ADVAPI32", b"ImpersonateLoggedOnUser", 4),
    spec(b"ADVAPI32", b"LogonUserA", 24),
    spec(b"ADVAPI32", b"LookupAccountSidA", 28),
    spec(b"ADVAPI32", b"LookupPrivilegeValueA", 12),
    spec(b"ADVAPI32", b"OpenSCManagerA", 12),
    spec(b"ADVAPI32", b"OpenServiceA", 12),
    spec(b"ADVAPI32", b"OpenThreadToken", 16),
    spec(b"ADVAPI32", b"QueryServiceConfigA", 16),
    spec(b"ADVAPI32", b"QueryServiceStatus", 8),
    spec(b"ADVAPI32", b"RegCreateKeyExA", 36),
    spec(b"ADVAPI32", b"RegOpenKeyA", 12),
    spec(b"ADVAPI32", b"RegOpenKeyExA", 20),
    spec(b"ADVAPI32", b"RegQueryValueExA", 24),
    spec(b"ADVAPI32", b"RegSetValueExA", 24),
    spec(b"ADVAPI32", b"StartServiceA", 12),
    spec(b"GDI32", b"GetDCOrgEx", 8),
    spec(b"GDI32", b"GetDeviceCaps", 8),
    spec(b"GDIPLUS", b"GdipCreateBitmapFromHBITMAP", 12),
    spec(b"GDIPLUS", b"GdipDisposeImage", 4),
    spec(b"GDIPLUS", b"GdipGetImageEncoders", 12),
    spec(b"GDIPLUS", b"GdipGetImageEncodersSize", 8),
    spec(b"GDIPLUS", b"GdipSaveImageToFile", 16),
    spec(b"GDIPLUS", b"GdiplusShutdown", 4),
    spec(b"GDIPLUS", b"GdiplusStartup", 12),
    spec(b"IPHLPAPI", b"GetIpNetTable", 12),
    spec(b"KERNEL32", b"AllocConsole", 0),
    spec(b"KERNEL32", b"FreeConsole", 0),
    spec(b"KERNEL32", b"AreFileApisANSI", 0),
    spec(b"KERNEL32", b"SetFileApisToANSI", 0),
    spec(b"KERNEL32", b"CopyFileA", 12),
    spec(b"KERNEL32", b"CreateFileMappingA", 24),
    spec(b"KERNEL32", b"OpenFileMappingA", 12),
    spec(b"KERNEL32", b"DeviceIoControl", 32),
    spec(b"KERNEL32", b"DosDateTimeToFileTime", 12),
    spec(b"KERNEL32", b"FileTimeToDosDateTime", 12),
    spec(b"KERNEL32", b"FindCloseChangeNotification", 4),
    spec(b"KERNEL32", b"FindFirstChangeNotificationA", 12),
    spec(b"KERNEL32", b"FindNextChangeNotification", 4),
    spec(b"KERNEL32", b"FlushConsoleInputBuffer", 4),
    spec(b"KERNEL32", b"FormatMessageA", 28),
    spec(b"KERNEL32", b"GenerateConsoleCtrlEvent", 8),
    spec(b"KERNEL32", b"GetCompressedFileSizeA", 8),
    spec(b"KERNEL32", b"GetConsoleCP", 0),
    spec(b"KERNEL32", b"GetConsoleCursorInfo", 8),
    spec(b"KERNEL32", b"GetConsoleOutputCP", 0),
    spec(b"KERNEL32", b"GetExitCodeThread", 8),
    spec(b"KERNEL32", b"GetFileSizeEx", 8),
    spec(b"KERNEL32", b"GetFileTime", 16),
    spec(b"KERNEL32", b"GetLargestConsoleWindowSize", 4),
    spec(b"KERNEL32", b"GetShortPathNameA", 12),
    spec(b"KERNEL32", b"GetSystemTimeAsFileTime", 4),
    spec(b"KERNEL32", b"GetThreadLocale", 0),
    spec(b"KERNEL32", b"GlobalAlloc", 8),
    spec(b"KERNEL32", b"GlobalLock", 4),
    spec(b"KERNEL32", b"GlobalMemoryStatus", 4),
    spec(b"KERNEL32", b"GlobalSize", 4),
    spec(b"KERNEL32", b"GlobalUnlock", 4),
    spec(b"KERNEL32", b"MapViewOfFile", 20),
    spec(b"KERNEL32", b"UnmapViewOfFile", 4),
    spec(b"KERNEL32", b"OpenProcess", 12),
    spec(b"KERNEL32", b"QueryDosDeviceA", 12),
    spec(b"KERNEL32", b"QueryPerformanceCounter", 4),
    spec(b"KERNEL32", b"QueryPerformanceFrequency", 4),
    spec(b"KERNEL32", b"SetConsoleCP", 4),
    spec(b"KERNEL32", b"SetConsoleCursorInfo", 8),
    spec(b"KERNEL32", b"SetConsoleIcon", 4),
    spec(b"KERNEL32", b"SetConsoleOutputCP", 4),
    spec(b"KERNEL32", b"SetEvent", 4),
    spec(b"KERNEL32", b"SetFileApisToOEM", 0),
    spec(b"KERNEL32", b"SetPriorityClass", 8),
    spec(b"KERNEL32", b"SetProcessShutdownParameters", 8),
    spec(b"KERNEL32", b"SetVolumeLabelA", 8),
    spec(b"KERNEL32", b"TerminateThread", 8),
    spec(b"KERNEL32", b"VirtualProtect", 16),
    spec(b"KERNEL32", b"WaitForSingleObjectEx", 12),
    spec(b"MPR", b"WNetAddConnection2A", 16),
    spec(b"MPR", b"WNetCancelConnection2A", 12),
    spec(b"MPR", b"WNetCloseEnum", 4),
    spec(b"MPR", b"WNetEnumResourceA", 16),
    spec(b"MPR", b"WNetGetConnectionA", 12),
    spec(b"MPR", b"WNetOpenEnumA", 20),
    spec(b"MPR", b"WNetGetUniversalNameA", 16),
    spec(b"NTDLL", b"NtQueryInformationFile", 20),
    spec(b"NTDLL", b"NtQueryObject", 20),
    spec(b"NTDLL", b"NtQuerySystemInformation", 16),
    spec(b"OLE32", b"CoCreateInstance", 20),
    spec(b"OLE32", b"CoGetMalloc", 8),
    spec(b"OLE32", b"CoInitialize", 4),
    spec(b"OLE32", b"OleFlushClipboard", 0),
    spec(b"OLE32", b"OleInitialize", 4),
    spec(b"OLE32", b"OleUninitialize", 0),
    spec(b"SHELL32", b"SHFileOperationA", 4),
    spec(b"SHELL32", b"SHGetDesktopFolder", 4),
    spec(b"SHELL32", b"SHGetFileInfoA", 20),
    spec(b"SHELL32", b"SHGetFolderPathA", 20),
    spec(b"SHELL32", b"SHGetSpecialFolderLocation", 12),
    spec(b"SHELL32", b"ShellExecuteA", 24),
    spec(b"SHELL32", b"Shell_NotifyIcon", 8),
    spec(b"SHELL32", b"ShellExecuteExA", 4),
    spec(b"USER32", b"AppendMenuA", 16),
    spec(b"USER32", b"BroadcastSystemMessage", 20),
    spec(b"USER32", b"CharLowerBuffA", 8),
    spec(b"USER32", b"CharToOemA", 8),
    spec(b"USER32", b"CharToOemBuffA", 12),
    spec(b"USER32", b"CharToOemW", 8),
    spec(b"USER32", b"CharUpperBuffA", 8),
    spec(b"USER32", b"CloseClipboard", 0),
    spec(b"USER32", b"CloseWindow", 4),
    spec(b"USER32", b"CreateDialogParamA", 20),
    spec(b"USER32", b"CreateMenu", 0),
    spec(b"USER32", b"CreatePopupMenu", 0),
    spec(b"USER32", b"CreateWindowExA", 48),
    spec(b"USER32", b"ChangeDisplaySettingsA", 8),
    spec(b"USER32", b"EnumDisplaySettingsA", 12),
    spec(b"USER32", b"DefWindowProcA", 16),
    spec(b"USER32", b"DeleteMenu", 12),
    spec(b"USER32", b"DestroyMenu", 4),
    spec(b"USER32", b"DestroyWindow", 4),
    spec(b"USER32", b"DispatchMessageA", 4),
    spec(b"USER32", b"DrawAnimatedRects", 16),
    spec(b"USER32", b"EmptyClipboard", 0),
    spec(b"USER32", b"IsClipboardFormatAvailable", 4),
    spec(b"USER32", b"EnumClipboardFormats", 4),
    spec(b"USER32", b"EnumWindows", 8),
    spec(b"USER32", b"ExitWindowsEx", 8),
    spec(b"USER32", b"FindWindowA", 8),
    spec(b"USER32", b"FindWindowExA", 16),
    spec(b"USER32", b"GetAsyncKeyState", 4),
    spec(b"USER32", b"GetClassInfoExA", 12),
    spec(b"USER32", b"GetCursorPos", 4),
    spec(b"USER32", b"GetDesktopWindow", 0),
    spec(b"USER32", b"GetForegroundWindow", 0),
    spec(b"USER32", b"GetKeyState", 4),
    spec(b"USER32", b"GetKeyboardState", 4),
    spec(b"USER32", b"GetLastActivePopup", 4),
    spec(b"USER32", b"GetMenuItemCount", 4),
    spec(b"USER32", b"GetMenuItemInfoA", 16),
    spec(b"USER32", b"GetMessageA", 16),
    spec(b"USER32", b"GetParent", 4),
    spec(b"USER32", b"GetWindow", 8),
    spec(b"USER32", b"GetWindowDC", 4),
    spec(b"USER32", b"GetWindowLongA", 8),
    spec(b"USER32", b"GetWindowPlacement", 8),
    spec(b"USER32", b"GetWindowRect", 8),
    spec(b"USER32", b"GetWindowTextA", 12),
    spec(b"USER32", b"GetWindowThreadProcessId", 8),
    spec(b"USER32", b"InsertMenuA", 20),
    spec(b"USER32", b"IsIconic", 4),
    spec(b"USER32", b"IsWindow", 4),
    spec(b"USER32", b"IsWindowVisible", 4),
    spec(b"USER32", b"IsZoomed", 4),
    spec(b"USER32", b"LoadIconA", 8),
    spec(b"USER32", b"LoadStringA", 16),
    spec(b"USER32", b"MessageBoxA", 16),
    spec(b"USER32", b"OemToCharA", 8),
    spec(b"USER32", b"OemToCharBuffA", 12),
    spec(b"USER32", b"OpenClipboard", 4),
    spec(b"USER32", b"OpenIcon", 4),
    spec(b"USER32", b"PeekMessageA", 20),
    spec(b"USER32", b"PostMessageA", 16),
    spec(b"USER32", b"PostThreadMessageA", 16),
    spec(b"USER32", b"RegisterClassExA", 4),
    spec(b"USER32", b"RegisterWindowMessageA", 4),
    spec(b"USER32", b"SendMessageA", 16),
    spec(b"USER32", b"SetClipboardData", 8),
    spec(b"USER32", b"SetCursorPos", 8),
    spec(b"USER32", b"SetForegroundWindow", 4),
    spec(b"USER32", b"SetMenuDefaultItem", 12),
    spec(b"USER32", b"SetMenuItemInfoA", 16),
    spec(b"USER32", b"SetWindowLongA", 12),
    spec(b"USER32", b"SetWindowPlacement", 8),
    spec(b"USER32", b"ShowWindowAsync", 8),
    spec(b"USER32", b"SystemParametersInfoA", 16),
    spec(b"USER32", b"TrackPopupMenu", 28),
    spec(b"USER32", b"UnregisterClassA", 8),
    spec(b"USER32", b"keybd_event", 16),
    spec(b"WININET", b"InternetCloseHandle", 4),
    spec(b"WININET", b"InternetOpenA", 20),
    spec(b"WININET", b"InternetOpenUrlA", 24),
    spec(b"WININET", b"InternetReadFile", 16),
    spec(b"WINMM", b"mciSendStringA", 16),
    spec(b"WINMM", b"timeKillEvent", 4),
    spec(b"WINMM", b"timeSetEvent", 20),
    spec(b"WSOCK32", b"WSACleanup", 0),
    spec(b"WSOCK32", b"WSAGetLastError", 0),
    spec(b"WSOCK32", b"WSASetLastError", 4),
    spec(b"WSOCK32", b"WSAStartup", 8),
    spec(b"WSOCK32", b"accept", 12),
    spec(b"WSOCK32", b"bind", 12),
    spec(b"WSOCK32", b"closesocket", 4),
    spec(b"WSOCK32", b"connect", 12),
    spec(b"WSOCK32", b"gethostbyname", 4),
    spec(b"WSOCK32", b"getsockname", 12),
    spec(b"WSOCK32", b"htons", 4),
    spec(b"WSOCK32", b"inet_addr", 4),
    spec(b"WSOCK32", b"inet_ntoa", 4),
    spec(b"WSOCK32", b"listen", 8),
    spec(b"WSOCK32", b"ntohs", 4),
    spec(b"WSOCK32", b"recv", 16),
    spec(b"WSOCK32", b"select", 20),
    spec(b"WSOCK32", b"send", 16),
    spec(b"WSOCK32", b"setsockopt", 20),
    spec(b"WSOCK32", b"shutdown", 8),
    spec(b"WSOCK32", b"socket", 12),
    spec(b"MSVCRT", b"__dllonexit", 0),
    spec(b"MSVCRT", b"_amsg_exit", 0),
    spec(b"MSVCRT", b"_initterm", 0),
    spec(b"MSVCRT", b"_lock", 0),
    spec(b"MSVCRT", b"_onexit", 0),
    spec(b"MSVCRT", b"_unlock", 0),
    spec(b"MSVCRT", b"abort", 0),
    spec(b"MSVCRT", b"calloc", 0),
    spec(b"MSVCRT", b"free", 0),
    spec(b"MSVCRT", b"fwrite", 0),
    spec(b"MSVCRT", b"malloc", 0),
    spec(b"MSVCRT", b"strcpy", 0),
    spec(b"MSVCRT", b"strlen", 0),
    spec(b"MSVCRT", b"strncmp", 0),
    spec(b"MSVCRT", b"vfprintf", 0),
    spec(b"ADVAPI32", b"AllocateAndInitializeSid", 44),
    spec(b"ADVAPI32", b"EqualSid", 8),
    spec(b"ADVAPI32", b"FreeSid", 4),
    spec(b"ADVAPI32", b"GetTokenInformation", 20),
    spec(b"ADVAPI32", b"OpenProcessToken", 12),
    spec(b"KERNEL32", b"Beep", 8),
    spec(b"KERNEL32", b"CompareStringA", 24),
    spec(b"KERNEL32", b"CompareStringW", 24),
    spec(b"KERNEL32", b"CreateConsoleScreenBuffer", 20),
    spec(b"KERNEL32", b"CreateDirectoryA", 8),
    spec(b"KERNEL32", b"CreateDirectoryW", 8),
    spec(b"KERNEL32", b"CreateFileW", 28),
    spec(b"KERNEL32", b"CreateMutexA", 12),
    spec(b"KERNEL32", b"CreatePipe", 16),
    spec(b"KERNEL32", b"CreateProcessA", 40),
    spec(b"KERNEL32", b"CreateProcessW", 40),
    spec(b"KERNEL32", b"CreateThread", 24),
    spec(b"KERNEL32", b"DeleteCriticalSection", 4),
    spec(b"KERNEL32", b"DeleteFileA", 4),
    spec(b"KERNEL32", b"DeleteFileW", 4),
    spec(b"KERNEL32", b"DuplicateHandle", 28),
    spec(b"KERNEL32", b"EnterCriticalSection", 4),
    spec(b"KERNEL32", b"ExitThread", 4),
    spec(b"KERNEL32", b"FileTimeToLocalFileTime", 8),
    spec(b"KERNEL32", b"FileTimeToSystemTime", 8),
    spec(b"KERNEL32", b"FillConsoleOutputAttribute", 20),
    spec(b"KERNEL32", b"FillConsoleOutputCharacterA", 20),
    spec(b"KERNEL32", b"FindClose", 4),
    spec(b"KERNEL32", b"FindFirstFileA", 8),
    spec(b"KERNEL32", b"FindFirstFileW", 8),
    spec(b"KERNEL32", b"FindNextFileA", 8),
    spec(b"KERNEL32", b"FindNextFileW", 8),
    spec(b"KERNEL32", b"FreeEnvironmentStringsA", 4),
    spec(b"KERNEL32", b"FreeEnvironmentStringsW", 4),
    spec(b"KERNEL32", b"FreeLibrary", 4),
    spec(b"KERNEL32", b"GetConsoleScreenBufferInfo", 8),
    spec(b"KERNEL32", b"GetCurrentDirectoryA", 8),
    spec(b"KERNEL32", b"GetCurrentDirectoryW", 8),
    spec(b"KERNEL32", b"GetCurrentProcess", 0),
    spec(b"KERNEL32", b"GetCurrentProcessId", 0),
    spec(b"KERNEL32", b"GetCurrentThread", 0),
    spec(b"KERNEL32", b"GetDiskFreeSpaceA", 20),
    spec(b"KERNEL32", b"GetDriveTypeA", 4),
    spec(b"KERNEL32", b"GetDriveTypeW", 4),
    spec(b"KERNEL32", b"GetEnvironmentStrings", 0),
    spec(b"KERNEL32", b"GetEnvironmentStringsW", 0),
    spec(b"KERNEL32", b"GetEnvironmentVariableA", 12),
    spec(b"KERNEL32", b"GetEnvironmentVariableW", 12),
    spec(b"KERNEL32", b"GetExitCodeProcess", 8),
    spec(b"KERNEL32", b"GetFileAttributesA", 4),
    spec(b"KERNEL32", b"GetFileAttributesW", 4),
    spec(b"KERNEL32", b"GetFileInformationByHandle", 8),
    spec(b"KERNEL32", b"GetFullPathNameA", 16),
    spec(b"KERNEL32", b"GetFullPathNameW", 16),
    spec(b"KERNEL32", b"GetLocalTime", 4),
    spec(b"KERNEL32", b"GetLocaleInfoA", 16),
    spec(b"KERNEL32", b"GetLocaleInfoW", 16),
    spec(b"KERNEL32", b"GetLogicalDriveStringsA", 8),
    spec(b"KERNEL32", b"GetLogicalDrives", 0),
    spec(b"KERNEL32", b"GetNumberOfConsoleInputEvents", 8),
    spec(b"KERNEL32", b"GetStringTypeA", 20),
    spec(b"KERNEL32", b"GetStringTypeW", 16),
    spec(b"KERNEL32", b"GetSystemTime", 4),
    spec(b"KERNEL32", b"GetTempPathA", 8),
    spec(b"KERNEL32", b"GetTickCount", 0),
    spec(b"KERNEL32", b"GetTimeZoneInformation", 4),
    spec(b"KERNEL32", b"GetUserDefaultLCID", 0),
    spec(b"KERNEL32", b"GetVersionExA", 4),
    spec(b"KERNEL32", b"GetVolumeInformationA", 32),
    spec(b"KERNEL32", b"HeapAlloc", 12),
    spec(b"KERNEL32", b"HeapCompact", 8),
    spec(b"KERNEL32", b"HeapCreate", 12),
    spec(b"KERNEL32", b"HeapDestroy", 4),
    spec(b"KERNEL32", b"HeapFree", 12),
    spec(b"KERNEL32", b"HeapReAlloc", 16),
    spec(b"KERNEL32", b"HeapSize", 12),
    spec(b"KERNEL32", b"HeapValidate", 12),
    spec(b"KERNEL32", b"HeapWalk", 8),
    spec(b"KERNEL32", b"InitializeCriticalSection", 4),
    spec(b"KERNEL32", b"InterlockedDecrement", 4),
    spec(b"KERNEL32", b"InterlockedIncrement", 4),
    spec(b"KERNEL32", b"IsBadCodePtr", 4),
    spec(b"KERNEL32", b"IsBadReadPtr", 8),
    spec(b"KERNEL32", b"IsBadWritePtr", 8),
    spec(b"KERNEL32", b"IsValidCodePage", 4),
    spec(b"KERNEL32", b"IsValidLocale", 8),
    spec(b"KERNEL32", b"LCMapStringA", 24),
    spec(b"KERNEL32", b"LCMapStringW", 24),
    spec(b"KERNEL32", b"LeaveCriticalSection", 4),
    spec(b"KERNEL32", b"LocalFileTimeToFileTime", 8),
    spec(b"KERNEL32", b"LockFile", 20),
    spec(b"KERNEL32", b"MoveFileA", 8),
    spec(b"KERNEL32", b"MoveFileW", 8),
    spec(b"KERNEL32", b"PeekConsoleInputA", 16),
    spec(b"KERNEL32", b"PeekNamedPipe", 24),
    spec(b"KERNEL32", b"RaiseException", 16),
    spec(b"KERNEL32", b"ReadConsoleA", 20),
    spec(b"KERNEL32", b"ReadConsoleOutputA", 20),
    spec(b"KERNEL32", b"ReleaseMutex", 4),
    spec(b"KERNEL32", b"RemoveDirectoryA", 4),
    spec(b"KERNEL32", b"RemoveDirectoryW", 4),
    spec(b"KERNEL32", b"ResumeThread", 4),
    spec(b"KERNEL32", b"RtlUnwind", 16),
    spec(b"KERNEL32", b"SetConsoleActiveScreenBuffer", 4),
    spec(b"KERNEL32", b"SetConsoleCursorPosition", 8),
    spec(b"KERNEL32", b"SetConsoleScreenBufferSize", 8),
    spec(b"KERNEL32", b"SetConsoleTitleA", 4),
    spec(b"KERNEL32", b"SetConsoleWindowInfo", 12),
    spec(b"KERNEL32", b"SetCurrentDirectoryA", 4),
    spec(b"KERNEL32", b"SetCurrentDirectoryW", 4),
    spec(b"KERNEL32", b"SetEndOfFile", 4),
    spec(b"KERNEL32", b"SetEnvironmentVariableW", 8),
    spec(b"KERNEL32", b"SetErrorMode", 4),
    spec(b"KERNEL32", b"SetFileAttributesA", 8),
    spec(b"KERNEL32", b"SetFileAttributesW", 8),
    spec(b"KERNEL32", b"SetFileTime", 16),
    spec(b"KERNEL32", b"SetHandleCount", 4),
    spec(b"KERNEL32", b"SetLastError", 4),
    spec(b"KERNEL32", b"SetLocalTime", 4),
    spec(b"KERNEL32", b"Sleep", 4),
    spec(b"KERNEL32", b"SystemTimeToFileTime", 8),
    spec(b"KERNEL32", b"TerminateProcess", 8),
    spec(b"KERNEL32", b"TlsAlloc", 0),
    spec(b"KERNEL32", b"TlsFree", 4),
    spec(b"KERNEL32", b"TlsGetValue", 4),
    spec(b"KERNEL32", b"TlsSetValue", 8),
    spec(b"KERNEL32", b"UnlockFile", 20),
    spec(b"KERNEL32", b"WaitForSingleObject", 8),
    spec(b"KERNEL32", b"WriteConsoleOutputA", 20),
    spec(b"KERNEL32", b"WriteConsoleOutputAttribute", 20),
    spec(b"KERNEL32", b"WriteConsoleOutputCharacterA", 20),
];

const fn spec(module: &'static [u8], name: &'static [u8], arg_bytes: u32) -> Spec {
    Spec { module, name, arg_bytes }
}

pub(super) fn lookup(module: &[u8], name: &[u8]) -> Option<&'static Spec> {
    let module = module_stem(module);
    SPECS.iter().find(|spec| {
        spec.module.eq_ignore_ascii_case(module) && spec.name.eq_ignore_ascii_case(name)
    })
}

fn module_stem(name: &[u8]) -> &[u8] {
    let end = name
        .iter()
        .rposition(|&b| b == b'.')
        .filter(|&at| name[at..].eq_ignore_ascii_case(b".DLL"))
        .unwrap_or(name.len());
    &name[..end]
}

pub(super) fn take_hold(console: &mut Console) -> bool {
    let held = console.hold;
    console.hold = false;
    held
}

pub(super) fn push_key(console: &mut Console, scancode: u8) {
    if scancode == 0xe0 {
        console.extended = true;
        return;
    }
    let down = scancode & 0x80 == 0;
    let scan = u16::from(scancode & 0x7f);
    let mut ascii = if down {
        crate::kernel::keyboard::scancode_to_ascii(scancode)
    } else {
        0
    };
    if scan == 0x1c {
        ascii = if down { b'\r' } else { 0 };
    }
    let vk = virtual_key(scan, if ascii.is_ascii_control() { 0 } else { ascii });
    if vk != 0 { console.keys[vk as usize] = if down { 0x80 } else { 0 }; }
    let control = u32::from(console.keys[0x12] != 0) * 2
        | u32::from(console.keys[0x11] != 0) * 8
        | u32::from(console.keys[0x10] != 0) * 16
        | u32::from(console.extended) * 256;
    console.extended = false;
    if console.input.len() < 64 {
        console.input.push(Key { down, ascii, scan, vk, control });
    }
}

/// CreateProcess from the Win32 personality feeds the shared fork/exec
/// mechanism. MSVCRT's system() passes COMSPEC plus "/c command"; unwrap that
/// request, then restore COMMAND.COM for DOS programs with launch overrides.
pub(super) fn create_process<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &Regs,
    wide: bool,
) -> Result<thread::KernelAction, u32> {
    let read_string = |address| {
        if wide { w_string(machine, address) } else { c_string(machine, address) }
    };
    let app = if arg(machine, regs, 0) == 0 {
        Vec::new()
    } else {
        read_string(arg(machine, regs, 0))?
    };
    let command = if arg(machine, regs, 1) == 0 {
        app.clone()
    } else {
        read_string(arg(machine, regs, 1))?
    };
    let (program, cmdtail) = command_program(&command, &app);
    if program.is_empty() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut path = windows_path(state, &program, false)?;
    if !crate::kernel::vfs::path_exists(&path) {
        return Err(ERROR_FILE_NOT_FOUND);
    }
    let mut cmdtail = cmdtail;
    if has_dos_launch_override(state, &program) {
        let data = crate::kernel::exec::load_file_resolved(&path)
            .map_err(|_| ERROR_FILE_NOT_FOUND)?;
        if matches!(
            crate::kernel::exec::detect_format(&data, &path),
            crate::kernel::exec::BinaryFormat::MzExe | crate::kernel::exec::BinaryFormat::Com
        ) {
            // COMMAND.COM owns LOADFIX.CFG parsing and the /L, DOS32A, and
            // virtual-IF launch paths. /E replaces this child with the DOS
            // program so MC's process handle tracks the program itself.
            let mut tail = b"/E ".to_vec();
            tail.extend_from_slice(&full_windows_path(state, &program));
            if !cmdtail.is_empty() {
                tail.push(b' ');
                tail.extend_from_slice(&cmdtail);
            }
            cmdtail = tail;
            path = windows_path(state, br"C:\RETROOS\COMMAND.COM", false)?;
        }
    }
    let cwd = if arg(machine, regs, 7) == 0 {
        Vec::new()
    } else {
        windows_path(state, &read_string(arg(machine, regs, 7))?, false)?
    };
    if path.len() > 164 || cwd.len() > 164 || cmdtail.len() > 127 {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let mut path_buf = [0; 164];
    path_buf[..path.len()].copy_from_slice(&path);
    let mut cwd_buf = [0; 164];
    cwd_buf[..cwd.len()].copy_from_slice(&cwd);
    let mut tail_buf = [0; 128];
    tail_buf[..cmdtail.len()].copy_from_slice(&cmdtail);

    let info = arg(machine, regs, 9) as usize;
    state.prepare_process(info);
    state.last_error = ERROR_FILE_NOT_FOUND;
    Ok(thread::KernelAction::ForkExec {
        path: path_buf,
        path_len: path.len(),
        cmdtail: tail_buf,
        cmdtail_len: cmdtail.len(),
        cwd: cwd_buf,
        cwd_len: cwd.len(),
        personality_name: None,
        policy: crate::kernel::dos::LaunchPolicy::default(),
        on_error: create_process_error,
        on_success: create_process_success,
    })
}

fn has_dos_launch_override(state: &WindowsState, program: &[u8]) -> bool {
    let Ok(path) = windows_path(state, br"C:\CONFIG\LOADFIX.CFG", false) else {
        return false;
    };
    let Ok(config) = crate::kernel::exec::load_file_resolved(&path) else {
        return false;
    };
    let name = program.rsplit(|&b| b == b'\\' || b == b'/').next().unwrap_or(program);
    loadfix_matches(&config, name)
}

fn loadfix_matches(config: &[u8], name: &[u8]) -> bool {
    config.split_inclusive(|&b| b == b'\n').any(|line| {
        // Mirror COMMAND.COM's 80-byte fgets buffer: overlong records are
        // discarded there and must not select a different launch path here.
        if line.len() > 79 {
            return false;
        }
        let line = line.trim_ascii_start();
        if line.is_empty() || line[0] == b'#' || line[0] == b';' {
            return false;
        }
        let end = line.iter().position(u8::is_ascii_whitespace).unwrap_or(line.len());
        line[..end].eq_ignore_ascii_case(name)
    })
}

const FILETIME_EPOCH: u64 = 11_644_473_600;

fn filetime(unix: u32) -> u64 {
    if unix == 0 { 0 } else { (u64::from(unix) + FILETIME_EPOCH) * 10_000_000 }
}

fn unix_from_filetime(value: u64) -> Option<i64> {
    i64::try_from(value / 10_000_000).ok().map(|seconds| seconds - FILETIME_EPOCH as i64)
}

fn system_time(unix: i64) -> [u16; 8] {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    [
        (year + i64::from(month <= 2)) as u16,
        month as u16,
        (days + 4).rem_euclid(7) as u16,
        day as u16,
        (seconds / 3_600) as u16,
        ((seconds / 60) % 60) as u16,
        (seconds % 60) as u16,
        0,
    ]
}

fn write_system_time<A: crate::Arch>(machine: &mut A, out: usize, unix: Option<i64>) -> u32 {
    let Some(unix) = unix else {
        machine.zero(out, 16);
        return 0;
    };
    for (index, field) in system_time(unix).iter().enumerate() {
        machine.write::<u16>(out + index * 2, *field);
    }
    1
}

fn create_process_error(regs: &mut Regs, _error: i32) {
    regs.rax = 0;
}

fn create_process_success(regs: &mut Regs, _child_tid: i32) {
    regs.rax = 1;
}

fn command_program(command: &[u8], app: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let shell = app.rsplit(|&b| b == b'\\' || b == b'/').next()
        .is_some_and(|name| name.eq_ignore_ascii_case(b"COMMAND.COM") || name.eq_ignore_ascii_case(b"CMD.EXE"));
    let mut text = command;
    if !app.is_empty() {
        if let Some((first, rest)) = take_word(text) {
            let same_app = first.eq_ignore_ascii_case(app)
                || first.rsplit(|&b| b == b'\\' || b == b'/').next()
                    .is_some_and(|name| app.rsplit(|&b| b == b'\\' || b == b'/')
                        .next().is_some_and(|app_name| name.eq_ignore_ascii_case(app_name)));
            if same_app {
                text = rest.trim_ascii_start();
            }
        }
        if !shell {
            return (app.to_vec(), text.trim_ascii_start().to_vec());
        }
    }
    if shell && text.len() >= 2 && text[..2].eq_ignore_ascii_case(b"/c") {
        text = text[2..].trim_ascii_start();
    }
    take_word(text).map_or((Vec::new(), Vec::new()), |(program, tail)| {
        (program.to_vec(), tail.trim_ascii_start().to_vec())
    })
}

fn take_word(text: &[u8]) -> Option<(&[u8], &[u8])> {
    let text = text.trim_ascii_start();
    if text.is_empty() { return None; }
    if text[0] == b'"' {
        let end = text[1..].iter().position(|&b| b == b'"')? + 1;
        Some((&text[1..end], &text[end + 1..]))
    } else {
        let end = text.iter().position(|b| b.is_ascii_whitespace()).unwrap_or(text.len());
        Some((&text[..end], &text[end..]))
    }
}

fn virtual_key(scan: u16, ascii: u8) -> u16 {
    match scan {
        0x01 => 0x1b,
        0x0e => 8,
        0x0f => 9,
        0x1d => 0x11,
        0x2a | 0x36 => 0x10,
        0x38 => 0x12,
        0x1c => 0x0d,
        0x48 => 0x26,
        0x50 => 0x28,
        0x4b => 0x25,
        0x4d => 0x27,
        0x47 => 0x24,
        0x4f => 0x23,
        0x49 => 0x21,
        0x51 => 0x22,
        0x53 => 0x2e,
        0x52 => 0x2d,
        0x3b..=0x44 => 0x70 + (scan - 0x3b),
        0x10..=0x19 => b"QWERTYUIOP"[(scan - 0x10) as usize] as u16,
        0x1e..=0x26 => b"ASDFGHJKL"[(scan - 0x1e) as usize] as u16,
        0x2c..=0x32 => b"ZXCVBNM"[(scan - 0x2c) as usize] as u16,
        _ if ascii.is_ascii_alphabetic() => u16::from(ascii.to_ascii_uppercase()),
        _ if ascii != 0 => u16::from(ascii),
        _ => 0,
    }
}

pub(super) fn call<A: crate::Arch>(
    machine: &mut A,
    kt: &mut thread::KernelThread<A>,
    state: &mut WindowsState,
    regs: &mut Regs,
    name: &[u8],
) -> u32 {
    if name.eq_ignore_ascii_case(b"GetTickCount") {
        return (machine.now() / 1_000_000) as u32;
    }
    if name.eq_ignore_ascii_case(b"GetCurrentProcess")
        || name.eq_ignore_ascii_case(b"GetCurrentThread")
    {
        return 0xffff_ffff;
    }
    if name.eq_ignore_ascii_case(b"FreeConsole") {
        // This personality keeps its console state per process; detaching
        // does not release the process's inherited file descriptors.
        state.console.hwnd = 0;
        return 1;
    }
    if name.eq_ignore_ascii_case(b"SetFileApisToANSI") {
        return 0; // File APIs already use the ANSI process encoding.
    }
    if name.eq_ignore_ascii_case(b"IsClipboardFormatAvailable") {
        return 0; // This personality does not publish clipboard formats yet.
    }
    if name.eq_ignore_ascii_case(b"GetCurrentProcessId") {
        return (kt.tid + 1) as u32;
    }
    if name.eq_ignore_ascii_case(b"GetUserDefaultLCID") {
        return 0x0409;
    }
    if name.eq_ignore_ascii_case(b"GetLogicalDrives") {
        return 1 << 2;
    }
    if name.eq_ignore_ascii_case(b"SetLastError") {
        state.last_error = arg(machine, regs, 0);
        return 0;
    }
    if name.eq_ignore_ascii_case(b"HeapCreate") {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"HeapAlloc") {
        return heap_alloc(machine, state, arg(machine, regs, 1), arg(machine, regs, 2));
    }
    if name.eq_ignore_ascii_case(b"HeapFree") {
        heap_free(state, arg(machine, regs, 2));
        return 1;
    }
    if name.eq_ignore_ascii_case(b"HeapReAlloc") {
        return heap_realloc(
            machine,
            state,
            arg(machine, regs, 1),
            arg(machine, regs, 2),
            arg(machine, regs, 3),
        );
    }
    if name.eq_ignore_ascii_case(b"HeapSize") {
        let addr = arg(machine, regs, 2);
        return state
            .blocks
            .iter()
            .find(|block| block.addr == addr && block.used)
            .map_or(0xffff_ffff, |block| block.size);
    }
    if name.eq_ignore_ascii_case(b"HeapDestroy")
        || name.eq_ignore_ascii_case(b"HeapValidate")
        || name.eq_ignore_ascii_case(b"InitializeCriticalSection")
        || name.eq_ignore_ascii_case(b"EnterCriticalSection")
        || name.eq_ignore_ascii_case(b"LeaveCriticalSection")
        || name.eq_ignore_ascii_case(b"DeleteCriticalSection")
        || name.eq_ignore_ascii_case(b"FreeLibrary")
        || name.eq_ignore_ascii_case(b"ReleaseMutex")
        || name.eq_ignore_ascii_case(b"SetEndOfFile")
        || name.eq_ignore_ascii_case(b"LockFile")
        || name.eq_ignore_ascii_case(b"UnlockFile")
        || name.eq_ignore_ascii_case(b"SetFileTime")
        || name.eq_ignore_ascii_case(b"SetFileAttributesA")
        || name.eq_ignore_ascii_case(b"SetFileAttributesW")
        || name.eq_ignore_ascii_case(b"SetErrorMode")
        || name.eq_ignore_ascii_case(b"SetConsoleTitleA")
        || name.eq_ignore_ascii_case(b"SetConsoleActiveScreenBuffer")
        || name.eq_ignore_ascii_case(b"Sleep")
        || name.eq_ignore_ascii_case(b"Beep")
        || name.eq_ignore_ascii_case(b"ResumeThread")
        || name.eq_ignore_ascii_case(b"SystemTimeToFileTime")
        || name.eq_ignore_ascii_case(b"FreeEnvironmentStringsA")
        || name.eq_ignore_ascii_case(b"FreeEnvironmentStringsW")
    {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"FileTimeToLocalFileTime")
        || name.eq_ignore_ascii_case(b"LocalFileTimeToFileTime")
    {
        let input = arg(machine, regs, 0) as usize;
        let output = arg(machine, regs, 1) as usize;
        machine.write::<u64>(output, machine.read::<u64>(input));
        return 1;
    }
    if name.eq_ignore_ascii_case(b"FileTimeToSystemTime") {
        let input = arg(machine, regs, 0) as usize;
        let output = arg(machine, regs, 1) as usize;
        return write_system_time(machine, output, unix_from_filetime(machine.read::<u64>(input)));
    }
    if name.eq_ignore_ascii_case(b"HeapCompact") || name.eq_ignore_ascii_case(b"HeapWalk") {
        return 0;
    }
    if name.eq_ignore_ascii_case(b"TlsAlloc") {
        let slot = tls_alloc(state);
        if slot == 0xffff_ffff {
            return fail(state, ERROR_INVALID_PARAMETER, slot);
        }
        state.last_error = 0;
        return slot;
    }
    if name.eq_ignore_ascii_case(b"TlsFree") {
        let slot = arg(machine, regs, 0);
        if slot < 64 {
            state.tls_mask &= !(1 << slot);
            state.last_error = 0;
            return 1;
        }
        return fail(state, ERROR_INVALID_PARAMETER, 0);
    }
    if name.eq_ignore_ascii_case(b"TlsGetValue") {
        let slot = arg(machine, regs, 0) as usize;
        if slot >= 64 {
            return fail(state, ERROR_INVALID_PARAMETER, 0);
        }
        state.last_error = 0;
        return state.tls[slot];
    }
    if name.eq_ignore_ascii_case(b"TlsSetValue") {
        let slot = arg(machine, regs, 0) as usize;
        if slot >= 64 {
            return fail(state, ERROR_INVALID_PARAMETER, 0);
        }
        state.tls[slot] = arg(machine, regs, 1);
        state.last_error = 0;
        return 1;
    }
    if name.eq_ignore_ascii_case(b"InterlockedIncrement")
        || name.eq_ignore_ascii_case(b"InterlockedDecrement")
    {
        let at = arg(machine, regs, 0) as usize;
        let delta = if name.eq_ignore_ascii_case(b"InterlockedIncrement") {
            1i32
        } else {
            -1
        };
        let value = (machine.read::<u32>(at) as i32).wrapping_add(delta) as u32;
        machine.write::<u32>(at, value);
        return value;
    }
    if name.eq_ignore_ascii_case(b"IsBadReadPtr")
        || name.eq_ignore_ascii_case(b"IsBadWritePtr")
        || name.eq_ignore_ascii_case(b"IsBadCodePtr")
    {
        return u32::from(arg(machine, regs, 0) == 0);
    }
    if name.eq_ignore_ascii_case(b"IsValidCodePage") || name.eq_ignore_ascii_case(b"IsValidLocale")
    {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"SetHandleCount") {
        return arg(machine, regs, 0).max(3);
    }
    if name.eq_ignore_ascii_case(b"DuplicateHandle") {
        let out = arg(machine, regs, 3) as usize;
        machine.write::<u32>(out, arg(machine, regs, 1));
        return 1;
    }
    if name.eq_ignore_ascii_case(b"WaitForSingleObject") {
        return 0;
    }
    if name.eq_ignore_ascii_case(b"CreateMutexA") {
        let handle = state.next_object;
        state.next_object += 1;
        return handle;
    }
    if name.eq_ignore_ascii_case(b"CreateConsoleScreenBuffer") {
        ensure_window(state);
        return 0x0004_0001;
    }
    if name.eq_ignore_ascii_case(b"GetConsoleScreenBufferInfo") {
        return screen_info(machine, state, arg(machine, regs, 1) as usize);
    }
    if name.eq_ignore_ascii_case(b"SetConsoleCursorPosition") {
        let coord = arg(machine, regs, 1);
        state.console.cursor_x = (coord & 0xffff) as u16;
        state.console.cursor_y = (coord >> 16) as u16;
        paint(state);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"SetConsoleScreenBufferSize") {
        // The text screen is fixed at 80x25. Honouring a larger size makes
        // Midnight Commander lay the panels out past the visible rows, so the
        // bottom of each panel never appears. Report success and keep 80x25.
        return 1;
    }
    if name.eq_ignore_ascii_case(b"SetConsoleWindowInfo") {
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetNumberOfConsoleInputEvents") {
        machine.write::<u32>(arg(machine, regs, 1) as usize, state.console.input.len() as u32);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"PeekConsoleInputA") || name.eq_ignore_ascii_case(b"ReadConsoleInputA")
    {
        let consume = name.eq_ignore_ascii_case(b"ReadConsoleInputA");
        return read_input(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3) as usize, consume);
    }
    if name.eq_ignore_ascii_case(b"ReadConsoleA") {
        return read_console_text(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3) as usize);
    }
    if name.eq_ignore_ascii_case(b"WriteConsoleOutputCharacterA") {
        return write_chars(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, false);
    }
    if name.eq_ignore_ascii_case(b"WriteConsoleOutputAttribute") {
        return write_chars(machine, state, arg(machine, regs, 1) as usize, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, true);
    }
    if name.eq_ignore_ascii_case(b"FillConsoleOutputCharacterA") {
        return fill_cells(machine, state, arg(machine, regs, 1) as u8, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, false);
    }
    if name.eq_ignore_ascii_case(b"FillConsoleOutputAttribute") {
        return fill_cells(machine, state, arg(machine, regs, 1) as u8, arg(machine, regs, 2), arg(machine, regs, 3), arg(machine, regs, 4) as usize, true);
    }
    if name.eq_ignore_ascii_case(b"WriteConsoleOutputA") {
        return console_block(machine, state, regs, false);
    }
    if name.eq_ignore_ascii_case(b"ReadConsoleOutputA") {
        return console_block(machine, state, regs, true);
    }
    if name.eq_ignore_ascii_case(b"GetCurrentDirectoryA") {
        return copy_dir(machine, state, arg(machine, regs, 0) as usize, arg(machine, regs, 1) as usize, false);
    }
    if name.eq_ignore_ascii_case(b"GetCurrentDirectoryW") {
        return copy_dir(machine, state, arg(machine, regs, 0) as usize, arg(machine, regs, 1) as usize, true);
    }
    if name.eq_ignore_ascii_case(b"SetCurrentDirectoryA") || name.eq_ignore_ascii_case(b"SetCurrentDirectoryW")
    {
        let wide = name.ends_with(b"W");
        let raw = if wide {
            w_string(machine, arg(machine, regs, 0))
        } else {
            c_string(machine, arg(machine, regs, 0))
        };
        let raw = match raw {
            Ok(v) => v,
            Err(error) => return fail(state, error, 0),
        };
        return set_directory(state, &raw);
    }
    if name.eq_ignore_ascii_case(b"GetFileAttributesA") || name.eq_ignore_ascii_case(b"GetFileAttributesW")
    {
        let wide = name.ends_with(b"W");
        let raw = if wide {
            w_string(machine, arg(machine, regs, 0))
        } else {
            c_string(machine, arg(machine, regs, 0))
        };
        let raw = match raw {
            Ok(v) => v,
            Err(error) => return fail(state, error, 0xffff_ffff),
        };
        return attributes(state, &raw);
    }
    if name.eq_ignore_ascii_case(b"FindFirstFileA") || name.eq_ignore_ascii_case(b"FindFirstFileW") {
        let wide = name.ends_with(b"W");
        let raw = if wide {
            w_string(machine, arg(machine, regs, 0))
        } else {
            c_string(machine, arg(machine, regs, 0))
        };
        let raw = match raw {
            Ok(v) => v,
            Err(error) => return fail(state, error, INVALID_HANDLE_VALUE),
        };
        return find_first(machine, state, &raw, arg(machine, regs, 1) as usize, wide);
    }
    if name.eq_ignore_ascii_case(b"FindNextFileA") || name.eq_ignore_ascii_case(b"FindNextFileW") {
        return find_next(machine, state, arg(machine, regs, 0), arg(machine, regs, 1) as usize);
    }
    if name.eq_ignore_ascii_case(b"FindClose") {
        let handle = arg(machine, regs, 0);
        state.finds.retain(|find| find.handle != handle);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"DeleteFileA") || name.eq_ignore_ascii_case(b"DeleteFileW")
        || name.eq_ignore_ascii_case(b"RemoveDirectoryA") || name.eq_ignore_ascii_case(b"RemoveDirectoryW")
        || name.eq_ignore_ascii_case(b"CreateDirectoryA") || name.eq_ignore_ascii_case(b"CreateDirectoryW")
    {
        return mutate_path(machine, state, regs, name);
    }
    if name.eq_ignore_ascii_case(b"MoveFileA") || name.eq_ignore_ascii_case(b"MoveFileW") {
        let wide = name.ends_with(b"W");
        let read = |n| if wide { w_string(machine, arg(machine, regs, n)) } else { c_string(machine, arg(machine, regs, n)) };
        let from = match read(0) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        let to = match read(1) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        let from = match windows_path(state, &from, false) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        let to = match windows_path(state, &to, true) { Ok(v) => v, Err(e) => return fail(state, e, 0) };
        return if crate::kernel::vfs::rename(&from, &to) < 0 { fail(state, ERROR_FILE_NOT_FOUND, 0) } else { 1 };
    }
    if name.eq_ignore_ascii_case(b"GetFullPathNameA") || name.eq_ignore_ascii_case(b"GetFullPathNameW") {
        return full_path(machine, state, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetLogicalDriveStringsA") {
        let text = b"C:\\\0";
        return copy_ascii(machine, arg(machine, regs, 1) as usize, arg(machine, regs, 0) as usize, text) + 1;
    }
    if name.eq_ignore_ascii_case(b"GetDriveTypeA") || name.eq_ignore_ascii_case(b"GetDriveTypeW") {
        return 3;
    }
    if name.eq_ignore_ascii_case(b"GetTempPathA") {
        let mut path = environment_value(&state.environment, b"TEMP")
            .filter(|value| !value.is_empty())
            .unwrap_or(b"C:\\TEMP")
            .to_vec();
        if !path.ends_with(b"\\") && !path.ends_with(b"/") {
            path.push(b'\\');
        }
        return copy_ascii(machine, arg(machine, regs, 1) as usize, arg(machine, regs, 0) as usize, &path);
    }
    if name.eq_ignore_ascii_case(b"GetDiskFreeSpaceA") {
        for n in 1..5 {
            let ptr = arg(machine, regs, n) as usize;
            if ptr != 0 {
                machine.write::<u32>(ptr, if n == 1 || n == 2 { 512 } else { 1024 * 1024 });
            }
        }
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetVolumeInformationA") {
        copy_ascii(machine, arg(machine, regs, 1) as usize, arg(machine, regs, 2) as usize, b"RETROOS");
        if arg(machine, regs, 4) != 0 {
            machine.write::<u32>(arg(machine, regs, 4) as usize, 255);
        }
        copy_ascii(machine, arg(machine, regs, 6) as usize, arg(machine, regs, 7) as usize, b"FAT");
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetEnvironmentStrings") {
        return env_block(machine, &state.environment, false);
    }
    if name.eq_ignore_ascii_case(b"GetEnvironmentStringsW") {
        return env_block(machine, &state.environment, true);
    }
    if name.eq_ignore_ascii_case(b"GetEnvironmentVariableA")
        || name.eq_ignore_ascii_case(b"GetEnvironmentVariableW") {
        let wide = name.ends_with(b"W");
        let key = match if wide { w_string(machine, arg(machine, regs, 0)) }
            else { c_string(machine, arg(machine, regs, 0)) } {
            Ok(key) => key,
            Err(error) => return fail(state, error, 0),
        };
        let Some(value) = environment_value(&state.environment, &key) else {
            return fail(state, 203, 0); // ERROR_ENVVAR_NOT_FOUND
        };
        let capacity = arg(machine, regs, 2) as usize;
        if capacity <= value.len() { return (value.len() + 1) as u32; }
        let output = arg(machine, regs, 1) as usize;
        if output == 0 { return fail(state, ERROR_INVALID_PARAMETER, 0); }
        return if wide { copy_dir_bytes(machine, output, capacity, value) }
        else { copy_ascii(machine, output, capacity, value) };
    }
    if name.eq_ignore_ascii_case(b"SetEnvironmentVariableW") {
        return set_environment(machine, state, regs, true);
    }
    if name.eq_ignore_ascii_case(b"SetFileSecurityA")
        || name.eq_ignore_ascii_case(b"SetFileSecurityW") {
        // The VFS has no Windows security-descriptor storage. Resolve the
        // import but report failure rather than pretend an ACL was changed.
        return fail(state, 50, 0); // ERROR_NOT_SUPPORTED
    }
    if name.eq_ignore_ascii_case(b"GetVersionExA") {
        return version(machine, arg(machine, regs, 0) as usize);
    }
    if name.eq_ignore_ascii_case(b"GetLocalTime") || name.eq_ignore_ascii_case(b"GetSystemTime")
        || name.eq_ignore_ascii_case(b"SetLocalTime")
    {
        if !name.starts_with(b"Set") {
            write_system_time(machine, arg(machine, regs, 0) as usize,
                crate::kernel::clock::rtc_unix_timestamp().map(i64::from));
        }
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetTimeZoneInformation") {
        machine.zero(arg(machine, regs, 0) as usize, 172);
        return 0;
    }
    if name.eq_ignore_ascii_case(b"CompareStringA") || name.eq_ignore_ascii_case(b"CompareStringW") {
        return compare(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"LCMapStringA") || name.eq_ignore_ascii_case(b"LCMapStringW") {
        return map_string(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetLocaleInfoA") || name.eq_ignore_ascii_case(b"GetLocaleInfoW") {
        return locale_info(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetStringTypeA") || name.eq_ignore_ascii_case(b"GetStringTypeW") {
        return string_type(machine, regs, name.ends_with(b"W"));
    }
    if name.eq_ignore_ascii_case(b"GetFileInformationByHandle") {
        let fd = arg(machine, regs, 0) as i32;
        let out = arg(machine, regs, 1) as usize;
        let Some((stat, mtime)) = crate::kernel::vfs::fd_info(fd, &kt.fds) else {
            return fail(state, ERROR_INVALID_HANDLE, 0);
        };
        machine.zero(out, 52);
        machine.write::<u32>(out, if stat.is_dir { 0x10 } else { 0x20 });
        machine.write::<u64>(out + 20, filetime(mtime));
        machine.write::<u32>(out + 36, stat.size);
        machine.write::<u32>(out + 40, 1);
        machine.write::<u64>(out + 44, stat.ino);
        return 1;
    }
    if name.eq_ignore_ascii_case(b"GetExitCodeProcess") {
        let handle = arg(machine, regs, 0);
        machine.write::<u32>(
            arg(machine, regs, 1) as usize,
            state.process_exit_code(handle).unwrap_or(259),
        );
        return 1;
    }
    if name.eq_ignore_ascii_case(b"CreateFileW") {
        let raw = match w_string(machine, arg(machine, regs, 0)) {
            Ok(v) => v,
            Err(error) => return fail(state, error, INVALID_HANDLE_VALUE),
        };
        return super::create_file(machine, kt, state, &raw, arg(machine, regs, 4));
    }
    if name.eq_ignore_ascii_case(b"CreateThread")
        || name.eq_ignore_ascii_case(b"CreatePipe")
        || name.eq_ignore_ascii_case(b"PeekNamedPipe")
        || name.eq_ignore_ascii_case(b"TerminateProcess")
        || name.eq_ignore_ascii_case(b"OpenProcessToken")
        || name.eq_ignore_ascii_case(b"GetTokenInformation")
        || name.eq_ignore_ascii_case(b"AllocateAndInitializeSid")
        || name.eq_ignore_ascii_case(b"EqualSid")
        || name.eq_ignore_ascii_case(b"FreeSid")
    {
        return fail(state, 120, 0);
    }
    if name.eq_ignore_ascii_case(b"ExitThread") || name.eq_ignore_ascii_case(b"RaiseException")
        || name.eq_ignore_ascii_case(b"RtlUnwind")
    {
        return 0;
    }
    system::call(machine, kt, state, regs, name)
}

fn tls_alloc(state: &mut WindowsState) -> u32 {
    for slot in 0..64 {
        if state.tls_mask & (1 << slot) == 0 {
            state.tls_mask |= 1 << slot;
            state.tls[slot] = 0;
            return slot as u32;
        }
    }
    0xffff_ffff
}

fn heap_alloc<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, flags: u32, bytes: u32) -> u32 {
    let size = bytes.max(1).next_multiple_of(8);
    if let Some(block) = state.blocks.iter_mut().find(|block| !block.used && block.size >= size) {
        block.used = true;
        if flags & 8 != 0 {
            machine.zero(block.addr as usize, block.size as usize);
        }
        return block.addr;
    }
    let addr = state.heap_next;
    let Some(end) = addr.checked_add(size) else {
        return 0;
    };
    if end >= super::USER_LIMIT {
        return 0;
    }
    state.heap_next = end;
    machine.zero(addr as usize, size as usize);
    machine.set_page_flags(addr as usize / 4096, size.div_ceil(4096) as usize, true, false);
    state.blocks.push(Block { addr, size, used: true });
    addr
}

fn heap_free(state: &mut WindowsState, addr: u32) {
    if let Some(block) = state.blocks.iter_mut().find(|block| block.addr == addr) {
        block.used = false;
    }
}

fn heap_realloc<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    flags: u32,
    addr: u32,
    bytes: u32,
) -> u32 {
    let old = state
        .blocks
        .iter()
        .find(|block| block.addr == addr && block.used)
        .map(|block| block.size)
        .unwrap_or(0);
    let next = heap_alloc(machine, state, flags, bytes);
    if next == 0 || addr == 0 {
        return next;
    }
    let n = old.min(bytes) as usize;
    for i in 0..n {
        let byte = machine.read::<u8>(addr as usize + i);
        machine.write::<u8>(next as usize + i, byte);
    }
    heap_free(state, addr);
    next
}

pub(super) fn open_console(state: &mut WindowsState) {
    ensure_window(state);
}

fn ensure_window(state: &mut WindowsState) {
    if state.console.hwnd != 0 {
        return;
    }
    let hwnd = state.next_object;
    state.next_object += 1;
    state.console.hwnd = hwnd;
    let width = state.console.cols as u32 * 8;
    let height = state.console.rows as u32 * 16;
    state.windows.push(Window {
        hwnd,
        parent: 0,
        wndproc: 0,
        x: 0,
        y: 0,
        width,
        height,
        visible: true,
        pixels: vec![0; width as usize * height as usize * 4],
    });
    paint(state);
}

fn paint(state: &mut WindowsState) {
    ensure_window(state);
    let hwnd = state.console.hwnd;
    let cols = state.console.cols as usize;
    let rows = state.console.rows as usize;
    let cells = state.console.cells.clone();
    let cursor = (state.console.cursor_x as usize, state.console.cursor_y as usize);
    let Some(window) = state.windows.iter_mut().find(|window| window.hwnd == hwnd) else {
        return;
    };
    for y in 0..rows {
        for x in 0..cols {
            let at = (y * cols + x) * 2;
            let ch = cells[at] as usize;
            let attr = cells[at + 1];
            let (fg, bg) = if cursor == (x, y) {
                (color(attr >> 4), color(attr))
            } else {
                (color(attr), color(attr >> 4))
            };
            let glyph = &lib::vga_fonts::FONT_8X16[ch.min(255) * 16..ch.min(255) * 16 + 16];
            for (row, &bits) in glyph.iter().enumerate().take(16) {
                for col in 0..8 {
                    let pixel = if bits & (0x80 >> col) != 0 { fg } else { bg };
                    let px = (y * 16 + row) * window.width as usize + x * 8 + col;
                    let dest = px * 4;
                    if dest + 4 <= window.pixels.len() {
                        window.pixels[dest..dest + 4].copy_from_slice(&pixel.to_le_bytes());
                    }
                }
            }
        }
    }
    state.dirty = true;
    crate::term::term().blit_cells(
        cols,
        rows,
        &cells,
        cursor.0,
        cursor.1,
    );
}

fn color(index: u8) -> u32 {
    const PALETTE: [u32; 16] = [
        0x000000, 0x0000aa, 0x00aa00, 0x00aaaa, 0xaa0000, 0xaa00aa, 0xaa5500, 0xaaaaaa, 0x555555,
        0x5555ff, 0x55ff55, 0x55ffff, 0xff5555, 0xff55ff, 0xffff55, 0xffffff,
    ];
    PALETTE[(index & 0x0f) as usize]
}

fn screen_info<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, out: usize) -> u32 {
    ensure_window(state);
    let console = &state.console;
    machine.write::<u16>(out, console.cols);
    machine.write::<u16>(out + 2, console.rows);
    machine.write::<u16>(out + 4, console.cursor_x);
    machine.write::<u16>(out + 6, console.cursor_y);
    machine.write::<u16>(out + 8, console.attr);
    machine.write::<u16>(out + 10, 0);
    machine.write::<u16>(out + 12, 0);
    machine.write::<u16>(out + 14, console.cols.saturating_sub(1));
    machine.write::<u16>(out + 16, console.rows.saturating_sub(1));
    machine.write::<u16>(out + 18, console.cols);
    machine.write::<u16>(out + 20, console.rows);
    1
}

/// `WriteConsoleOutputA` / `ReadConsoleOutputA`. Midnight Commander paints each
/// panel as one `CHAR_INFO` rectangle; ignoring that buffer left only the
/// stray text (the hotlist notice) that was written a character at a time.
fn console_block<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    regs: &Regs,
    read: bool,
) -> u32 {
    let buffer = arg(machine, regs, 1) as usize;
    let size = arg(machine, regs, 2);
    let origin = arg(machine, regs, 3);
    let region = arg(machine, regs, 4) as usize;
    let buf_w = (size & 0xffff) as i32;
    let buf_h = (size >> 16) as i32;
    let origin_x = (origin & 0xffff) as i32;
    let origin_y = (origin >> 16) as i32;
    if region == 0 || buf_w <= 0 || buf_h <= 0 {
        return 0;
    }
    ensure_window(state);
    let cols = i32::from(state.console.cols);
    let rows = i32::from(state.console.rows);
    let left = i32::from(machine.read::<i16>(region));
    let top = i32::from(machine.read::<i16>(region + 2));
    let right = i32::from(machine.read::<i16>(region + 4));
    let bottom = i32::from(machine.read::<i16>(region + 6));
    if right < left || bottom < top {
        return 0;
    }
    let src_x0 = origin_x;
    let src_y0 = origin_y;
    let clip_left = left.clamp(0, cols);
    let clip_top = top.clamp(0, rows);
    let clip_right = right.clamp(-1, cols - 1);
    let clip_bottom = bottom.clamp(-1, rows - 1);
    if clip_right >= clip_left && clip_bottom >= clip_top {
        for row in clip_top..=clip_bottom {
            for col in clip_left..=clip_right {
                let sx = src_x0 + (col - left);
                let sy = src_y0 + (row - top);
                if sx < 0 || sy < 0 || sx >= buf_w || sy >= buf_h {
                    continue;
                }
                let guest = buffer + (sy as usize * buf_w as usize + sx as usize) * 4;
                let screen = (row as usize * cols as usize + col as usize) * 2;
                if read {
                    machine.write::<u16>(guest, u16::from(state.console.cells[screen]));
                    machine.write::<u16>(guest + 2, u16::from(state.console.cells[screen + 1]));
                } else {
                    state.console.cells[screen] = machine.read::<u16>(guest) as u8;
                    state.console.cells[screen + 1] = machine.read::<u16>(guest + 2) as u8;
                }
            }
        }
    }
    machine.write::<i16>(region, clip_left as i16);
    machine.write::<i16>(region + 2, clip_top as i16);
    machine.write::<i16>(region + 4, clip_right as i16);
    machine.write::<i16>(region + 6, clip_bottom as i16);
    if !read {
        paint(state);
    }
    1
}

pub(super) fn write_console_text<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    src: usize,
    len: usize,
) {
    ensure_window(state);
    for i in 0..len {
        let byte = machine.read::<u8>(src + i);
        match byte {
            b'\r' => state.console.cursor_x = 0,
            b'\n' => {
                state.console.cursor_x = 0;
                if state.console.cursor_y + 1 < state.console.rows {
                    state.console.cursor_y += 1;
                }
            }
            ch => {
                let x = state.console.cursor_x;
                let y = state.console.cursor_y;
                let cols = state.console.cols;
                let at = (y as usize * cols as usize + x as usize) * 2;
                if at + 1 < state.console.cells.len() {
                    state.console.cells[at] = ch;
                    state.console.cells[at + 1] = state.console.attr as u8;
                }
                if x + 1 < cols {
                    state.console.cursor_x = x + 1;
                } else {
                    state.console.cursor_x = 0;
                    if y + 1 < state.console.rows {
                        state.console.cursor_y = y + 1;
                    }
                }
            }
        }
    }
    paint(state);
}

fn write_chars<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    src: usize,
    len: u32,
    coord: u32,
    written: usize,
    attrs: bool,
) -> u32 {
    ensure_window(state);
    let x = (coord & 0xffff) as u16;
    let y = (coord >> 16) as u16;
    let start = y as usize * state.console.cols as usize + x as usize;
    let room = state.console.cols as usize * state.console.rows as usize;
    let n = (len as usize).min(room.saturating_sub(start));
    for i in 0..n {
        let at = (start + i) * 2;
        if attrs {
            state.console.cells[at + 1] = machine.read::<u16>(src + i * 2) as u8;
        } else {
            state.console.cells[at] = machine.read::<u8>(src + i);
        }
    }
    if written != 0 {
        machine.write::<u32>(written, n as u32);
    }
    paint(state);
    1
}

fn fill_cells<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    value: u8,
    len: u32,
    coord: u32,
    written: usize,
    attrs: bool,
) -> u32 {
    ensure_window(state);
    let x = (coord & 0xffff) as u16;
    let y = (coord >> 16) as u16;
    let start = y as usize * state.console.cols as usize + x as usize;
    let room = state.console.cols as usize * state.console.rows as usize;
    let n = (len as usize).min(room.saturating_sub(start));
    for i in 0..n {
        let at = (start + i) * 2;
        if attrs {
            state.console.cells[at + 1] = value;
        } else {
            state.console.cells[at] = value;
        }
    }
    if written != 0 {
        machine.write::<u32>(written, n as u32);
    }
    paint(state);
    1
}

pub(super) fn read_input<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    buf: usize,
    count: u32,
    read: usize,
    consume: bool,
) -> u32 {
    if consume && state.console.input.is_empty() {
        state.console.hold = true;
        return 0;
    }
    let n = (count as usize).min(state.console.input.len()).min(16);
    for i in 0..n {
        let key = &state.console.input[i];
        let at = buf + i * 20;
        machine.write::<u16>(at, 1);
        machine.write::<u32>(at + 4, u32::from(key.down));
        machine.write::<u16>(at + 8, 1);
        machine.write::<u16>(at + 10, key.vk);
        machine.write::<u16>(at + 12, key.scan);
        machine.write::<u16>(at + 14, u16::from(key.ascii));
        machine.write::<u32>(at + 16, key.control);
    }
    if consume {
        state.console.input.drain(..n);
    }
    if read != 0 {
        machine.write::<u32>(read, n as u32);
    }
    1
}

fn read_console_text<A: crate::Arch>(
    machine: &mut A,
    state: &mut WindowsState,
    buf: usize,
    cap: u32,
    read: usize,
) -> u32 {
    let mut n = 0;
    while n < cap as usize {
        let Some(pos) = state.console.input.iter().position(|key| key.down && key.ascii != 0) else {
            break;
        };
        let ascii = state.console.input[pos].ascii;
        state.console.input.remove(pos);
        machine.write::<u8>(buf + n, ascii);
        n += 1;
        if ascii == b'\r' || ascii == b'\n' {
            break;
        }
    }
    if read != 0 {
        machine.write::<u32>(read, n as u32);
    }
    1
}

fn current_dos(state: &WindowsState) -> Vec<u8> {
    if state.cwd_len == 0 {
        return b"C:\\".to_vec();
    }
    guest_windows_path(state.cwd_str())
}

fn copy_dir<A: crate::Arch>(machine: &mut A, state: &WindowsState, cap: usize, out: usize, wide: bool) -> u32 {
    let text = current_dos(state);
    if wide {
        if out == 0 {
            return (text.len() + 1) as u32;
        }
        let n = text.len().min(cap.saturating_sub(1));
        for (i, &byte) in text[..n].iter().enumerate() {
            machine.write::<u16>(out + i * 2, u16::from(byte));
        }
        machine.write::<u16>(out + n * 2, 0);
        n as u32
    } else if out == 0 {
        (text.len() + 1) as u32
    } else {
        copy_ascii(machine, out, cap, &text)
    }
}

fn set_directory(state: &mut WindowsState, raw: &[u8]) -> u32 {
    let path = match windows_path(state, raw, false) {
        Ok(path) => path,
        Err(error) => return fail(state, error, 0),
    };
    if !crate::kernel::vfs::dir_exists(&path) && !crate::kernel::vfs::path_exists(&path) {
        return fail(state, ERROR_FILE_NOT_FOUND, 0);
    }
    let n = path.len().min(state.cwd.len());
    state.cwd[..n].copy_from_slice(&path[..n]);
    state.cwd_len = n;
    1
}

fn attributes(state: &mut WindowsState, raw: &[u8]) -> u32 {
    let mut text = raw.to_vec();
    while text.last().is_some_and(|b| *b == b'\\' || *b == b'/') {
        text.pop();
    }
    let path = match windows_path(state, &text, false) {
        Ok(path) => path,
        Err(_) => return fail(state, ERROR_FILE_NOT_FOUND, 0xffff_ffff),
    };
    if crate::kernel::vfs::dir_exists(&path) {
        return 0x10;
    }
    match crate::kernel::vfs::stat(&path, true) {
        Some(stat) if stat.is_dir => 0x10,
        Some(_) => 0x20,
        None => fail(state, ERROR_FILE_NOT_FOUND, 0xffff_ffff),
    }
}

fn split_pattern(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let Some(split) = raw.iter().rposition(|&b| b == b'\\' || b == b'/') else {
        return (Vec::new(), raw.to_vec());
    };
    let dir_end = if split == 2 && raw.get(1) == Some(&b':') { 3 } else { split };
    let dir = raw[..dir_end].to_vec();
    let name = if split + 1 == raw.len() { b"*".to_vec() } else { raw[split + 1..].to_vec() };
    (dir, name)
}

fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    if pattern == b"*" || pattern == b"*.*" {
        return true;
    }
    let mut pi = 0;
    let mut ni = 0;
    let mut star = None;
    let mut mark = 0;
    let pat = pattern;
    while ni < name.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi].eq_ignore_ascii_case(&name[ni])) {
            pi += 1;
            ni += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ni;
        } else if let Some(at) = star {
            pi = at + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

fn find_first<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, raw: &[u8], out: usize, wide: bool) -> u32 {
    let (dir, pattern) = split_pattern(raw);
    let path = match windows_path(state, &dir, false) {
        Ok(path) => path,
        Err(error) => return fail(state, error, INVALID_HANDLE_VALUE),
    };
    let mut entries = Vec::new();
    let dot = pattern == b".";
    let dotdot = pattern == b"..";
    if dot || pattern == b"*" || pattern == b"*.*" {
        entries.push(Entry { name: b".".to_vec(), short: b".".to_vec(), size: 0, mtime: 0, dir: true });
    }
    if dotdot || pattern == b"*" || pattern == b"*.*" {
        entries.push(Entry { name: b"..".to_vec(), short: b"..".to_vec(), size: 0, mtime: 0, dir: true });
    }
    if !dot && !dotdot {
        let mut index = 0;
        while let Some(item) = crate::kernel::vfs::readdir(&path, index) {
            index += 1;
            if item.name == b"." || item.name == b".." || !glob_match(&pattern, &item.name) {
                continue;
            }
            entries.push(Entry {
                name: item.name,
                short: item.short_name.map(|s| s.as_bytes().to_vec()).unwrap_or_default(),
                size: item.size,
                mtime: item.mtime,
                dir: item.is_dir,
            });
        }
    }
    if entries.is_empty() {
        return fail(state, ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE);
    }
    write_find(machine, out, &entries[0], wide);
    let handle = state.next_find;
    state.next_find += 1;
    state.finds.push(Find { handle, entries, index: 1, wide });
    handle
}

fn find_next<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, handle: u32, out: usize) -> u32 {
    let Some(find) = state.finds.iter_mut().find(|find| find.handle == handle) else {
        return fail(state, ERROR_INVALID_HANDLE, 0);
    };
    if find.index >= find.entries.len() {
        return fail(state, 18, 0);
    }
    write_find(machine, out, &find.entries[find.index], find.wide);
    find.index += 1;
    1
}

fn write_find<A: crate::Arch>(machine: &mut A, out: usize, entry: &Entry, wide: bool) {
    machine.zero(out, if wide { 592 } else { 318 });
    machine.write::<u32>(out, if entry.dir { 0x10 } else { 0x20 });
    machine.write::<u64>(out + 20, filetime(entry.mtime));
    machine.write::<u32>(out + 32, entry.size);
    if wide {
        for (i, &byte) in entry.name.iter().take(259).enumerate() {
            machine.write::<u16>(out + 44 + i * 2, u16::from(byte));
        }
        for (i, &byte) in entry.short.iter().take(13).enumerate() {
            machine.write::<u16>(out + 564 + i * 2, u16::from(byte));
        }
    } else {
        let n = entry.name.len().min(259);
        machine.copy_to(out + 44, &entry.name[..n]);
        let s = entry.short.len().min(13);
        if s != 0 {
            machine.copy_to(out + 304, &entry.short[..s]);
        }
    }
}

fn mutate_path<A: crate::Arch>(
    machine: &A,
    state: &mut WindowsState,
    regs: &Regs,
    name: &[u8],
) -> u32 {
    let wide = name.ends_with(b"W");
    let raw = if wide {
        w_string(machine, arg(machine, regs, 0))
    } else {
        c_string(machine, arg(machine, regs, 0))
    };
    let raw = match raw {
        Ok(v) => v,
        Err(error) => return fail(state, error, 0),
    };
    let create = name.starts_with(b"Create");
    let path = match windows_path(state, &raw, create) {
        Ok(path) => path,
        Err(error) => return fail(state, error, 0),
    };
    let rc = if name.starts_with(b"Delete") {
        crate::kernel::vfs::delete(&path)
    } else if name.starts_with(b"Remove") {
        crate::kernel::vfs::rmdir(&path)
    } else {
        crate::kernel::vfs::mkdir(&path)
    };
    if rc < 0 { 0 } else { 1 }
}

fn full_path<A: crate::Arch>(machine: &mut A, state: &WindowsState, regs: &Regs, wide: bool) -> u32 {
    let raw = if wide {
        w_string(machine, arg(machine, regs, 0))
    } else {
        c_string(machine, arg(machine, regs, 0))
    };
    let raw = match raw {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let absolute = full_windows_path(state, &raw);
    let cap = arg(machine, regs, 1) as usize;
    let buf = arg(machine, regs, 2) as usize;
    let part = arg(machine, regs, 3) as usize;
    let file = absolute.iter().rposition(|&b| b == b'\\').map(|n| n + 1).unwrap_or(0);
    if part != 0 && buf != 0 {
        let width = if wide { 2 } else { 1 };
        machine.write::<u32>(part, buf as u32 + (file * width) as u32);
    }
    if wide {
        copy_dir_bytes(machine, buf, cap, &absolute)
    } else {
        copy_ascii(machine, buf, cap, &absolute)
    }
}

fn copy_dir_bytes<A: crate::Arch>(machine: &mut A, out: usize, cap: usize, text: &[u8]) -> u32 {
    if cap == 0 || out == 0 {
        return (text.len() + 1) as u32;
    }
    let n = text.len().min(cap - 1);
    for (i, &byte) in text[..n].iter().enumerate() {
        machine.write::<u16>(out + i * 2, u16::from(byte));
    }
    machine.write::<u16>(out + n * 2, 0);
    n as u32
}

fn environment_value<'a>(environment: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    environment.split(|&byte| byte == 0)
        .take_while(|entry| !entry.is_empty())
        .find_map(|entry| {
            let eq = entry.iter().position(|&byte| byte == b'=')?;
            entry[..eq].eq_ignore_ascii_case(key).then_some(&entry[eq + 1..])
        })
}

pub(super) fn set_environment<A: crate::Arch>(machine: &mut A, state: &mut WindowsState,
    regs: &Regs, wide: bool) -> u32 {
    let read = |ptr| if wide { w_string(machine, ptr) } else { c_string(machine, ptr) };
    let key = match read(arg(machine, regs, 0)) {
        Ok(key) if !key.is_empty() && !key.contains(&b'=') => key,
        _ => return fail(state, ERROR_INVALID_PARAMETER, 0),
    };
    let value_ptr = arg(machine, regs, 1);
    let value = if value_ptr == 0 { None } else {
        match read(value_ptr) {
            Ok(value) => Some(value),
            Err(error) => return fail(state, error, 0),
        }
    };
    let mut environment = Vec::new();
    for entry in state.environment.split(|&b| b == 0).take_while(|entry| !entry.is_empty()) {
        if entry.iter().position(|&b| b == b'=').is_some_and(|eq| entry[..eq].eq_ignore_ascii_case(&key)) {
            continue;
        }
        environment.extend_from_slice(entry);
        environment.push(0);
    }
    if let Some(value) = value {
        environment.extend_from_slice(&key);
        environment.push(b'=');
        environment.extend_from_slice(&value);
        environment.push(0);
    }
    environment.push(0);
    if environment.len() == 1 { environment.push(0); }
    // env_block reserves one page for ANSI and two for the wide view.
    if environment.len() > 4096 { return fail(state, 8, 0); }
    state.environment = environment;
    1
}

#[cfg(test)]
mod environment_tests {
    use super::{command_program, environment_value, filetime, loadfix_matches, system_time,
                unix_from_filetime, windows_environment};

    #[test]
    fn windows_process_receives_config_and_inherited_values() {
        let env = windows_environment(b"temp=D:\\SCRATCH\0MCHOME=C:\\RETROOS\\MC\0HOME=C:\\CONFIG\\MC\0\0");
        assert_eq!(environment_value(&env, b"TEMP"), Some(&b"D:\\SCRATCH"[..]));
        assert_eq!(environment_value(&env, b"MCHOME"), Some(&b"C:\\RETROOS\\MC"[..]));
        assert_eq!(environment_value(&env, b"HOME"), Some(&b"C:\\CONFIG\\MC"[..]));
        assert_eq!(environment_value(&env, b"COMSPEC"), Some(&b"C:\\RETROOS\\COMMAND.COM"[..]));
        assert!(env.ends_with(b"\0\0"));
    }

    #[test]
    fn windows_dos_launch_recognizes_command_overrides() {
        let (program, tail) = command_program(
            br#""C:\RETROOS\COMMAND.COM" /c "C:\GAMES\DOOM\DOOM.EXE" -nomusic"#,
            br"C:\RETROOS\COMMAND.COM");
        assert_eq!(program, br"C:\GAMES\DOOM\DOOM.EXE");
        assert_eq!(tail, b"-nomusic");
        let cfg = b"# a comment\nDOOM.EXE repair\r\nWOLF3D.EXE iopl3\n";
        assert!(loadfix_matches(cfg, b"doom.exe"));
        assert!(loadfix_matches(cfg, b"WOLF3D.EXE"));
        assert!(!loadfix_matches(cfg, b"DOOM2.EXE"));
        assert!(!loadfix_matches(b"# DOOM.EXE repair\n", b"DOOM.EXE"));
        let long = [b'X'; 80];
        assert!(!loadfix_matches(&long, b"X"));
    }

    #[test]
    fn windows_file_times_use_vfs_seconds() {
        let unix = 1_700_000_000;
        assert_eq!(unix_from_filetime(filetime(unix)), Some(i64::from(unix)));
        assert_eq!(system_time(i64::from(unix)), [2023, 11, 2, 14, 22, 13, 20, 0]);
        assert_eq!(filetime(0), 0);
        assert_eq!(system_time(unix_from_filetime(0).unwrap()), [1601, 1, 1, 1, 0, 0, 0, 0]);
    }
}

/// Merge the DOS startup environment into the Windows process environment.
/// Windows CRTs read this through GetEnvironmentStrings at process startup.
pub(super) fn windows_environment(dos: &[u8]) -> Vec<u8> {
    let mut entries: Vec<Vec<u8>> = [
        b"COMSPEC=C:\\RETROOS\\COMMAND.COM".to_vec(),
        b"PATH=C:\\RETROOS;C:\\".to_vec(),
        b"TEMP=C:\\TEMP".to_vec(),
    ].into();
    for entry in dos.split(|&byte| byte == 0).take_while(|entry| !entry.is_empty()) {
        let Some(eq) = entry.iter().position(|&byte| byte == b'=') else { continue };
        if eq == 0 { continue; }
        if let Some(old) = entries.iter().position(|old| old[..old.iter().position(|&b| b == b'=').unwrap()]
            .eq_ignore_ascii_case(&entry[..eq])) {
            entries[old] = entry.to_vec();
        } else {
            entries.push(entry.to_vec());
        }
    }
    let mut out = Vec::new();
    for entry in entries {
        if out.len() + entry.len() + 2 > 4096 { break; }
        out.extend_from_slice(&entry);
        out.push(0);
    }
    out.push(0);
    out
}

fn env_block<A: crate::Arch>(machine: &mut A, environment: &[u8], wide: bool) -> u32 {
    const ENV: usize = 0x7ff1_0000;
    machine.zero(ENV, 3 * 4096);
    machine.copy_to(ENV, environment);
    for (i, &byte) in environment.iter().enumerate() {
        machine.write::<u16>(ENV + 4096 + i * 2, u16::from(byte));
    }
    machine.set_page_flags(ENV / 4096, 3, true, false);
    (ENV + if wide { 4096 } else { 0 }) as u32
}

fn version<A: crate::Arch>(machine: &mut A, out: usize) -> u32 {
    let size = machine.read::<u32>(out);
    machine.zero(out, size.min(156) as usize);
    machine.write::<u32>(out, size);
    machine.write::<u32>(out + 4, 4);
    machine.write::<u32>(out + 8, 0);
    machine.write::<u32>(out + 12, 1381);
    machine.write::<u32>(out + 16, 2);
    1
}

fn taken<A: crate::Arch>(machine: &A, ptr: u32, count: i32, wide: bool) -> Vec<u8> {
    if count < 0 {
        return if wide { w_string(machine, ptr).unwrap_or_default() } else { c_string(machine, ptr).unwrap_or_default() };
    }
    let n = count as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let byte = if wide { machine.read::<u16>(ptr as usize + i * 2) as u8 } else { machine.read::<u8>(ptr as usize + i) };
        out.push(byte);
    }
    out
}

fn compare<A: crate::Arch>(machine: &A, regs: &Regs, wide: bool) -> u32 {
    let flags = arg(machine, regs, 1);
    let mut left = taken(machine, arg(machine, regs, 2), arg(machine, regs, 3) as i32, wide);
    let mut right = taken(machine, arg(machine, regs, 4), arg(machine, regs, 5) as i32, wide);
    if flags & 1 != 0 {
        for byte in left.iter_mut().chain(right.iter_mut()) {
            *byte = byte.to_ascii_uppercase();
        }
    }
    match left.cmp(&right) {
        core::cmp::Ordering::Less => 1,
        core::cmp::Ordering::Equal => 2,
        core::cmp::Ordering::Greater => 3,
    }
}

fn map_string<A: crate::Arch>(machine: &mut A, regs: &Regs, wide: bool) -> u32 {
    let flags = arg(machine, regs, 1);
    let mut text = taken(machine, arg(machine, regs, 2), arg(machine, regs, 3) as i32, wide);
    if flags & 0x200 != 0 {
        for byte in &mut text { *byte = byte.to_ascii_uppercase(); }
    } else if flags & 0x100 != 0 {
        for byte in &mut text { *byte = byte.to_ascii_lowercase(); }
    }
    let dest = arg(machine, regs, 4) as usize;
    let cap = arg(machine, regs, 5) as usize;
    if dest == 0 || cap == 0 {
        return (text.len() + 1) as u32;
    }
    let n = text.len().min(cap);
    for (i, &byte) in text[..n].iter().enumerate() {
        if wide { machine.write::<u16>(dest + i * 2, u16::from(byte)); }
        else { machine.write::<u8>(dest + i, byte); }
    }
    n as u32
}

fn locale_info<A: crate::Arch>(machine: &mut A, regs: &Regs, wide: bool) -> u32 {
    let kind = arg(machine, regs, 1) & 0xffff;
    let text: &[u8] = match kind {
        0x1004 => b"1252",
        0x1001 | 0x0001 => b"English",
        _ => b"",
    };
    if text.is_empty() {
        return 0;
    }
    let dest = arg(machine, regs, 2) as usize;
    let cap = arg(machine, regs, 3) as usize;
    if dest == 0 || cap == 0 {
        return (text.len() + 1) as u32;
    }
    if wide { copy_dir_bytes(machine, dest, cap, text) } else { copy_ascii(machine, dest, cap, text) }
}

fn string_type<A: crate::Arch>(machine: &mut A, regs: &Regs, wide: bool) -> u32 {
    let (src, count, dest) = if wide {
        (arg(machine, regs, 1), arg(machine, regs, 2) as i32, arg(machine, regs, 3) as usize)
    } else {
        (arg(machine, regs, 2), arg(machine, regs, 3) as i32, arg(machine, regs, 4) as usize)
    };
    let text = taken(machine, src, count, wide);
    for (i, &byte) in text.iter().enumerate() {
        let mut kind = 0u16;
        if byte.is_ascii_uppercase() { kind |= 0x0001 | 0x0100; }
        if byte.is_ascii_lowercase() { kind |= 0x0002 | 0x0100; }
        if byte.is_ascii_digit() { kind |= 0x0004 | 0x0200; }
        if byte.is_ascii_whitespace() { kind |= 0x0008 | 0x0800; }
        if byte.is_ascii_punctuation() { kind |= 0x0010 | 0x0400; }
        if byte.is_ascii_control() { kind |= 0x0020; }
        machine.write::<u16>(dest + i * 2, kind);
    }
    1
}

pub(super) fn thread_stack<A: crate::Arch>(machine: &mut A, state: &mut WindowsState, size: u32) -> u32 { heap_alloc(machine, state, 8, size) }

pub(super) fn thread_stack_free(state: &mut WindowsState, base: u32) { heap_free(state, base); }
