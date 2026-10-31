"""Wine DLLs installed as the sole Windows runtime.

NTDLL and WIN32U are built from Wine with named RETROOS.DLL imports.
WIN32U contains Wine drawing/windowing and FreeType font rendering as PE code.
Display and session-service integration is still in progress.
"""

WINE_DLLS = [
    "advapi32", "combase", "comctl32", "comdlg32", "coml2", "gdi32",
    "imm32", "kernel32", "kernelbase", "msacm32", "msvcrt", "ole32",
    "oleaut32", "rpcrt4", "sechost", "shcore", "shell32", "shlwapi",
    "ucrtbase", "user32", "version", "winmm", "mpr", "cryptbase",
]

# These are PE modules containing Wine's Win16 adapters, not standalone NE
# DLLs. Preserve their names; the WOW loader must bind their 16-bit exports.
WINE_WIN16 = [ "user.exe16", "gdi.exe16", "mmsystem.dll16", "commdlg.dll16", "win87em.dll16", "system.drv16", "comm.drv16"]

WINE_FILES = {
    "//lib/wine:" + name + "_dll": "RETROOS/WINDOWS/SYSTEM32/" + name.upper() + ".DLL"
    for name in WINE_DLLS
}
WINE_FILES.update({
    "@wine_pe//:pe/" + name: "RETROOS/WINDOWS/SYSTEM/" + name.upper()
    for name in WINE_WIN16
})
WINE_FILES.update({
    "//lib/wine/ntdll:KRNL386.EXE16": "RETROOS/WINDOWS/SYSTEM/KRNL386.EXE16",
    "//lib/wine/ntdll:WIN32U.DLL": "RETROOS/WINDOWS/SYSTEM32/WIN32U.DLL",
    "//lib/wine/ntdll:NTDLL.DLL": "RETROOS/WINDOWS/SYSTEM32/NTDLL.DLL",
    "//lib/wine:retroos_dll": "RETROOS/WINDOWS/SYSTEM32/RETROOS.DLL",
    "@wine_source//:COPYING.LIB": "RETROOS/WINDOWS/WINE-LICENSE.TXT",
    "//lib/wine:SOURCE.txt": "RETROOS/WINDOWS/WINE-SOURCE.TXT",
})

# Complete NLS data from the pinned Wine source, including the C-locale ASCII table.
WINE_NLS = [
    "c_037", "c_10000", "c_10001", "c_10002", "c_10003", "c_10004", "c_10005", "c_10006",
    "c_10007", "c_10008", "c_10010", "c_10017", "c_10021", "c_10029", "c_10079", "c_10081",
    "c_10082", "c_1026", "c_1250", "c_1251", "c_1252", "c_1253", "c_1254", "c_1255",
    "c_1256", "c_1257", "c_1258", "c_1361", "c_20127", "c_20866", "c_20932", "c_20949",
    "c_21866", "c_28591", "c_28592", "c_28593", "c_28594", "c_28595", "c_28596", "c_28597",
    "c_28598", "c_28599", "c_28603", "c_28605", "c_437", "c_500", "c_708", "c_720",
    "c_737", "c_775", "c_850", "c_852", "c_855", "c_857", "c_860", "c_861",
    "c_862", "c_863", "c_864", "c_865", "c_866", "c_869", "c_874", "c_875",
    "c_932", "c_936", "c_949", "c_950", "l_intl", "locale", "normidna", "normnfc",
    "normnfd", "normnfkc", "normnfkd", "sortdefault",
]
WINE_FILES.update({"@wine_source//:nls/" + name + ".nls": "RETROOS/WINDOWS/SYSTEM32/" + name + ".nls" for name in WINE_NLS})

# Wine's redistributable fonts, from the same pinned source as WIN32U.
WINE_FONTS = ["courier", "fixedsys", "fixedsys_jp", "marlett", "ms_sans_serif",
              "small_fonts", "small_fonts_jp", "symbol", "system", "tahoma",
              "tahomabd", "webdings", "wingding"]
WINE_FILES.update({"@wine_source//:fonts/" + name + ".ttf": "RETROOS/WINDOWS/fonts/" + name + ".ttf" for name in WINE_FONTS})
WINE_FILES["//lib/wine:freetype_license"] = "RETROOS/WINDOWS/FREETYPE-LICENSE.TXT"
