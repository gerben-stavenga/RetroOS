"""Wine DLLs installed as the sole Windows runtime.

NTDLL is built from Wine with named RETROOS.DLL imports. WIN32U is the upstream PE entry surface;
its syscall implementation still needs the RetroOS userspace backend.
"""

WINE_DLLS = [
    "advapi32", "combase", "comctl32", "comdlg32", "coml2", "gdi32",
    "imm32", "kernel32", "kernelbase", "msacm32", "msvcrt", "ole32",
    "oleaut32", "rpcrt4", "sechost", "shcore", "shell32", "shlwapi",
    "ucrtbase", "user32", "version", "win32u", "winmm", "mpr", "cryptbase",
]

# These are PE modules containing Wine's Win16 adapters, not standalone NE
# DLLs. Preserve their names; the WOW loader must bind their 16-bit exports.
WINE_WIN16 = ["krnl386.exe16", "user.exe16", "gdi.exe16", "mmsystem.dll16", "commdlg.dll16", "win87em.dll16"]

WINE_FILES = {
    "//lib/wine:" + name + "_dll": "RETROOS/WINDOWS/SYSTEM32/" + name.upper() + ".DLL"
    for name in WINE_DLLS
}
WINE_FILES.update({
    "@wine_pe//:pe/" + name: "RETROOS/WINDOWS/SYSTEM/" + name.upper()
    for name in WINE_WIN16
})
WINE_FILES.update({
    "//lib/wine/ntdll:NTDLL.DLL": "RETROOS/WINDOWS/SYSTEM32/NTDLL.DLL",
    "//lib/wine:retroos_dll": "RETROOS/WINDOWS/SYSTEM32/RETROOS.DLL",
    "@wine_source//:COPYING.LIB": "RETROOS/WINDOWS/WINE-LICENSE.TXT",
    "//lib/wine:SOURCE.txt": "RETROOS/WINDOWS/WINE-SOURCE.TXT",
})
