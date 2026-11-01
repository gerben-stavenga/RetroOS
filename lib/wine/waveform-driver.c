/*
 * WINMM functions
 *
 * Copyright 1993      Martin Ayotte
 *           1998-2002 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */


/* Wine 1.2 dlls/winmm/winmm.c waveform wrappers, using the multimedia
 * driver interface retained by Wine 11. This backend needs no WASAPI host.
 * Source: https://github.com/wine-mirror/wine/blob/wine-1.2/dlls/winmm/winmm.c
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#include "windef.h"
#include "winbase.h"
#include "mmsystem.h"
#include "winuser.h"
#include "winnls.h"
#include "winternl.h"
#include "winemm.h"

#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winmm);

static UINT WAVE_Open(HANDLE* lphndl, UINT uDeviceID, UINT uType,
                      LPCWAVEFORMATEX lpFormat, DWORD_PTR dwCallback,
                      DWORD_PTR dwInstance, DWORD dwFlags)
{
    HANDLE		handle;
    LPWINE_MLD		wmld;
    DWORD		dwRet = MMSYSERR_NOERROR;
    WAVEOPENDESC	wod;

    TRACE("(%p, %d, %s, %p, %08lX, %08lX, %08X);\n",
	  lphndl, (int)uDeviceID, (uType==MMDRV_WAVEOUT)?"Out":"In", lpFormat, dwCallback,
	  dwInstance, dwFlags);

    if (dwFlags & WAVE_FORMAT_QUERY)
        TRACE("WAVE_FORMAT_QUERY requested !\n");

    if (lpFormat == NULL) {
        WARN("bad format\n");
        return WAVERR_BADFORMAT;
    }

    if ((dwFlags & WAVE_MAPPED) && (uDeviceID == (UINT)-1)) {
        WARN("invalid parameter\n");
	return MMSYSERR_INVALPARAM;
    }

    /* may have a PCMWAVEFORMAT rather than a WAVEFORMATEX so don't read cbSize */
    TRACE("wFormatTag=%u, nChannels=%u, nSamplesPerSec=%u, nAvgBytesPerSec=%u, nBlockAlign=%u, wBitsPerSample=%u\n",
	  lpFormat->wFormatTag, lpFormat->nChannels, lpFormat->nSamplesPerSec,
	  lpFormat->nAvgBytesPerSec, lpFormat->nBlockAlign, lpFormat->wBitsPerSample);

    if ((wmld = MMDRV_Alloc(sizeof(WINE_WAVE), uType, &handle,
			    &dwFlags, &dwCallback, &dwInstance)) == NULL) {
        WARN("no memory\n");
	return MMSYSERR_NOMEM;
    }

    wod.hWave = handle;
    wod.lpFormat = (LPWAVEFORMATEX)lpFormat;  /* should the struct be copied iso pointer? */
    wod.dwCallback = dwCallback;
    wod.dwInstance = dwInstance;
    wod.dnDevNode = 0L;

    TRACE("cb=%08lx\n", wod.dwCallback);

    for (;;) {
        if (dwFlags & WAVE_MAPPED) {
            wod.uMappedDeviceID = uDeviceID;
            uDeviceID = WAVE_MAPPER;
        } else {
            wod.uMappedDeviceID = -1;
        }
        wmld->uDeviceID = uDeviceID;

        dwRet = MMDRV_Open(wmld, (uType == MMDRV_WAVEOUT) ? WODM_OPEN : WIDM_OPEN,
                           (DWORD_PTR)&wod, dwFlags);

        TRACE("dwRet = %s\n", WINMM_ErrorToString(dwRet));
        if (dwRet != WAVERR_BADFORMAT ||
            ((dwFlags & (WAVE_MAPPED|WAVE_FORMAT_DIRECT)) != 0) || (uDeviceID == WAVE_MAPPER)) break;
        /* if we ask for a format which isn't supported by the physical driver,
         * let's try to map it through the wave mapper (except, if we already tried
         * or user didn't allow us to use acm codecs or the device is already the mapper)
         */
        dwFlags |= WAVE_MAPPED;
        /* we shall loop only one */
    }

    if ((dwFlags & WAVE_FORMAT_QUERY) || dwRet != MMSYSERR_NOERROR) {
        MMDRV_Free(handle, wmld);
        handle = 0;
    }

    if (lphndl != NULL) *lphndl = handle;
    TRACE("=> %s hWave=%p\n", WINMM_ErrorToString(dwRet), handle);

    return dwRet;
}

/**************************************************************************
 * 				waveOutGetNumDevs		[WINMM.@]
 */
UINT WINAPI waveOutGetNumDevs(void)
{
    return MMDRV_GetNum(MMDRV_WAVEOUT);
}

/**************************************************************************
 * 				waveOutGetDevCapsA		[WINMM.@]
 */
UINT WINAPI waveOutGetDevCapsA(UINT_PTR uDeviceID, LPWAVEOUTCAPSA lpCaps,
			       UINT uSize)
{
    WAVEOUTCAPSW	wocW;
    UINT 		ret;

    if (lpCaps == NULL)        return MMSYSERR_INVALPARAM;

    ret = waveOutGetDevCapsW(uDeviceID, &wocW, sizeof(wocW));

    if (ret == MMSYSERR_NOERROR) {
	WAVEOUTCAPSA wocA;
	wocA.wMid           = wocW.wMid;
	wocA.wPid           = wocW.wPid;
	wocA.vDriverVersion = wocW.vDriverVersion;
        WideCharToMultiByte( CP_ACP, 0, wocW.szPname, -1, wocA.szPname,
                             sizeof(wocA.szPname), NULL, NULL );
	wocA.dwFormats      = wocW.dwFormats;
	wocA.wChannels      = wocW.wChannels;
	wocA.dwSupport      = wocW.dwSupport;
	memcpy(lpCaps, &wocA, min(uSize, sizeof(wocA)));
    }
    return ret;
}

/**************************************************************************
 * 				waveOutGetDevCapsW		[WINMM.@]
 */
UINT WINAPI waveOutGetDevCapsW(UINT_PTR uDeviceID, LPWAVEOUTCAPSW lpCaps,
			       UINT uSize)
{
    LPWINE_MLD		wmld;

    TRACE("(%lu %p %u)!\n", uDeviceID, lpCaps, uSize);

    if (lpCaps == NULL)	return MMSYSERR_INVALPARAM;

    if ((wmld = MMDRV_Get((HANDLE)uDeviceID, MMDRV_WAVEOUT, TRUE)) == NULL)
        return MMSYSERR_BADDEVICEID;

    return MMDRV_Message(wmld, WODM_GETDEVCAPS, (DWORD_PTR)lpCaps, uSize);
}

/**************************************************************************
 * 				waveOutGetErrorTextA 	[WINMM.@]
 * 				waveInGetErrorTextA 	[WINMM.@]
 */
UINT WINAPI waveOutGetErrorTextA(UINT uError, LPSTR lpText, UINT uSize)
{
    UINT	ret;

    if (lpText == NULL) ret = MMSYSERR_INVALPARAM;
    else if (uSize == 0) ret = MMSYSERR_NOERROR;
    else
    {
        LPWSTR	xstr = HeapAlloc(GetProcessHeap(), 0, uSize * sizeof(WCHAR));
        if (!xstr) ret = MMSYSERR_NOMEM;
        else
        {
            ret = waveOutGetErrorTextW(uError, xstr, uSize);
            if (ret == MMSYSERR_NOERROR)
                WideCharToMultiByte(CP_ACP, 0, xstr, -1, lpText, uSize, NULL, NULL);
            HeapFree(GetProcessHeap(), 0, xstr);
        }
    }
    return ret;
}

/**************************************************************************
 * 				waveOutGetErrorTextW 	[WINMM.@]
 * 				waveInGetErrorTextW 	[WINMM.@]
 */
UINT WINAPI waveOutGetErrorTextW(UINT uError, LPWSTR lpText, UINT uSize)
{
    UINT        ret = MMSYSERR_BADERRNUM;

    if (lpText == NULL) ret = MMSYSERR_INVALPARAM;
    else if (uSize == 0) ret = MMSYSERR_NOERROR;
    else if (
	       /* test has been removed because MMSYSERR_BASE is 0, and gcc did emit
		* a warning for the test was always true */
	       (/*uError >= MMSYSERR_BASE && */ uError <= MMSYSERR_LASTERROR) ||
	       (uError >= WAVERR_BASE  && uError <= WAVERR_LASTERROR)) {
	if (LoadStringW(hWinMM32Instance,
			uError, lpText, uSize) > 0) {
	    ret = MMSYSERR_NOERROR;
	}
    }
    return ret;
}

/**************************************************************************
 *			waveOutOpen			[WINMM.@]
 * All the args/structs have the same layout as the win16 equivalents
 */
MMRESULT WINAPI waveOutOpen(LPHWAVEOUT lphWaveOut, UINT uDeviceID,
                       LPCWAVEFORMATEX lpFormat, DWORD_PTR dwCallback,
                       DWORD_PTR dwInstance, DWORD dwFlags)
{
    return WAVE_Open((HANDLE*)lphWaveOut, uDeviceID, MMDRV_WAVEOUT, lpFormat,
                     dwCallback, dwInstance, dwFlags);
}

/**************************************************************************
 * 				waveOutClose		[WINMM.@]
 */
UINT WINAPI waveOutClose(HWAVEOUT hWaveOut)
{
    LPWINE_MLD		wmld;
    DWORD		dwRet;

    TRACE("(%p)\n", hWaveOut);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    dwRet = MMDRV_Close(wmld, WODM_CLOSE);
    if (dwRet != WAVERR_STILLPLAYING)
	MMDRV_Free(hWaveOut, wmld);

    return dwRet;
}

/**************************************************************************
 * 				waveOutPrepareHeader	[WINMM.@]
 */
UINT WINAPI waveOutPrepareHeader(HWAVEOUT hWaveOut,
				 WAVEHDR* lpWaveOutHdr, UINT uSize)
{
    LPWINE_MLD		wmld;
    UINT		result;

    TRACE("(%p, %p, %u);\n", hWaveOut, lpWaveOutHdr, uSize);

    if (lpWaveOutHdr == NULL || uSize < sizeof (WAVEHDR))
	return MMSYSERR_INVALPARAM;

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    if ((result = MMDRV_Message(wmld, WODM_PREPARE, (DWORD_PTR)lpWaveOutHdr,
                                uSize)) != MMSYSERR_NOTSUPPORTED)
        return result;

    if (lpWaveOutHdr->dwFlags & WHDR_INQUEUE)
	return WAVERR_STILLPLAYING;

    lpWaveOutHdr->dwFlags |= WHDR_PREPARED;
    lpWaveOutHdr->dwFlags &= ~WHDR_DONE;

    return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				waveOutUnprepareHeader	[WINMM.@]
 */
UINT WINAPI waveOutUnprepareHeader(HWAVEOUT hWaveOut,
				   LPWAVEHDR lpWaveOutHdr, UINT uSize)
{
    LPWINE_MLD		wmld;
    UINT		result;

    TRACE("(%p, %p, %u);\n", hWaveOut, lpWaveOutHdr, uSize);

    if (lpWaveOutHdr == NULL || uSize < sizeof (WAVEHDR))
	return MMSYSERR_INVALPARAM;

    if (!(lpWaveOutHdr->dwFlags & WHDR_PREPARED)) {
	return MMSYSERR_NOERROR;
    }

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    if ((result = MMDRV_Message(wmld, WODM_UNPREPARE, (DWORD_PTR)lpWaveOutHdr,
                                uSize)) != MMSYSERR_NOTSUPPORTED)
        return result;

    if (lpWaveOutHdr->dwFlags & WHDR_INQUEUE)
	return WAVERR_STILLPLAYING;

    lpWaveOutHdr->dwFlags &= ~WHDR_PREPARED;
    lpWaveOutHdr->dwFlags |= WHDR_DONE;

    return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				waveOutWrite		[WINMM.@]
 */
UINT WINAPI waveOutWrite(HWAVEOUT hWaveOut, LPWAVEHDR lpWaveOutHdr,
			 UINT uSize)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p, %u);\n", hWaveOut, lpWaveOutHdr, uSize);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WODM_WRITE, (DWORD_PTR)lpWaveOutHdr, uSize);
}

/**************************************************************************
 * 				waveOutBreakLoop	[WINMM.@]
 */
UINT WINAPI waveOutBreakLoop(HWAVEOUT hWaveOut)
{
    LPWINE_MLD		wmld;

    TRACE("(%p);\n", hWaveOut);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_BREAKLOOP, 0L, 0L);
}

/**************************************************************************
 * 				waveOutPause		[WINMM.@]
 */
UINT WINAPI waveOutPause(HWAVEOUT hWaveOut)
{
    LPWINE_MLD		wmld;

    TRACE("(%p);\n", hWaveOut);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_PAUSE, 0L, 0L);
}

/**************************************************************************
 * 				waveOutReset		[WINMM.@]
 */
UINT WINAPI waveOutReset(HWAVEOUT hWaveOut)
{
    LPWINE_MLD		wmld;

    TRACE("(%p);\n", hWaveOut);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_RESET, 0L, 0L);
}

/**************************************************************************
 * 				waveOutRestart		[WINMM.@]
 */
UINT WINAPI waveOutRestart(HWAVEOUT hWaveOut)
{
    LPWINE_MLD		wmld;

    TRACE("(%p);\n", hWaveOut);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_RESTART, 0L, 0L);
}

/**************************************************************************
 * 				waveOutGetPosition	[WINMM.@]
 */
UINT WINAPI waveOutGetPosition(HWAVEOUT hWaveOut, LPMMTIME lpTime,
			       UINT uSize)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p, %u);\n", hWaveOut, lpTime, uSize);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WODM_GETPOS, (DWORD_PTR)lpTime, uSize);
}

/**************************************************************************
 * 				waveOutGetPitch		[WINMM.@]
 */
UINT WINAPI waveOutGetPitch(HWAVEOUT hWaveOut, LPDWORD lpdw)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p);\n", hWaveOut, lpdw);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_GETPITCH, (DWORD_PTR)lpdw, 0L);
}

/**************************************************************************
 * 				waveOutSetPitch		[WINMM.@]
 */
UINT WINAPI waveOutSetPitch(HWAVEOUT hWaveOut, DWORD dw)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %08x);\n", hWaveOut, dw);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_SETPITCH, dw, 0L);
}

/**************************************************************************
 * 				waveOutGetPlaybackRate	[WINMM.@]
 */
UINT WINAPI waveOutGetPlaybackRate(HWAVEOUT hWaveOut, LPDWORD lpdw)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p);\n", hWaveOut, lpdw);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_GETPLAYBACKRATE, (DWORD_PTR)lpdw, 0L);
}

/**************************************************************************
 * 				waveOutSetPlaybackRate	[WINMM.@]
 */
UINT WINAPI waveOutSetPlaybackRate(HWAVEOUT hWaveOut, DWORD dw)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %08x);\n", hWaveOut, dw);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
        return MMSYSERR_INVALHANDLE;
    return MMDRV_Message(wmld, WODM_SETPLAYBACKRATE, dw, 0L);
}

/**************************************************************************
 * 				waveOutGetVolume	[WINMM.@]
 */
UINT WINAPI waveOutGetVolume(HWAVEOUT hWaveOut, LPDWORD lpdw)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p);\n", hWaveOut, lpdw);

    if (lpdw == NULL) {
        WARN("invalid parameter\n");
        return MMSYSERR_INVALPARAM;
    }

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, TRUE)) == NULL)
        return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WODM_GETVOLUME, (DWORD_PTR)lpdw, 0L);
}

/**************************************************************************
 * 				waveOutSetVolume	[WINMM.@]
 */
UINT WINAPI waveOutSetVolume(HWAVEOUT hWaveOut, DWORD dw)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %08x);\n", hWaveOut, dw);

     if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, TRUE)) == NULL)
        return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WODM_SETVOLUME, dw, 0L);
}

/**************************************************************************
 * 				waveOutGetID		[WINMM.@]
 */
UINT WINAPI waveOutGetID(HWAVEOUT hWaveOut, UINT* lpuDeviceID)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p);\n", hWaveOut, lpuDeviceID);

    if (lpuDeviceID == NULL) return MMSYSERR_INVALHANDLE;

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    *lpuDeviceID = wmld->uDeviceID;
    return 0;
}

/**************************************************************************
 * 				waveOutMessage 		[WINMM.@]
 */
UINT WINAPI waveOutMessage(HWAVEOUT hWaveOut, UINT uMessage,
                           DWORD_PTR dwParam1, DWORD_PTR dwParam2)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %u, %ld, %ld)\n", hWaveOut, uMessage, dwParam1, dwParam2);

    if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, FALSE)) == NULL) {
	if ((wmld = MMDRV_Get(hWaveOut, MMDRV_WAVEOUT, TRUE)) != NULL) {
	    return MMDRV_PhysicalFeatures(wmld, uMessage, dwParam1, dwParam2);
	}
        WARN("invalid handle\n");
	return MMSYSERR_INVALHANDLE;
    }

    /* from M$ KB */
    if (uMessage < DRVM_IOCTL || (uMessage >= DRVM_IOCTL_LAST && uMessage < DRVM_MAPPER)) {
        WARN("invalid parameter\n");
	return MMSYSERR_INVALPARAM;
    }

    return MMDRV_Message(wmld, uMessage, dwParam1, dwParam2);
}

/**************************************************************************
 * 				waveInGetNumDevs 		[WINMM.@]
 */
UINT WINAPI waveInGetNumDevs(void)
{
    return MMDRV_GetNum(MMDRV_WAVEIN);
}

/**************************************************************************
 * 				waveInGetDevCapsW 		[WINMM.@]
 */
UINT WINAPI waveInGetDevCapsW(UINT_PTR uDeviceID, LPWAVEINCAPSW lpCaps, UINT uSize)
{
    LPWINE_MLD		wmld;

    TRACE("(%lu %p %u)!\n", uDeviceID, lpCaps, uSize);

    if (lpCaps == NULL)	return MMSYSERR_INVALPARAM;

    if ((wmld = MMDRV_Get((HANDLE)uDeviceID, MMDRV_WAVEIN, TRUE)) == NULL)
	return MMSYSERR_BADDEVICEID;

    return MMDRV_Message(wmld, WIDM_GETDEVCAPS, (DWORD_PTR)lpCaps, uSize);
}

/**************************************************************************
 * 				waveInGetDevCapsA 		[WINMM.@]
 */
UINT WINAPI waveInGetDevCapsA(UINT_PTR uDeviceID, LPWAVEINCAPSA lpCaps, UINT uSize)
{
    WAVEINCAPSW		wicW;
    UINT		ret;

    if (lpCaps == NULL)	return MMSYSERR_INVALPARAM;

    ret = waveInGetDevCapsW(uDeviceID, &wicW, sizeof(wicW));

    if (ret == MMSYSERR_NOERROR) {
	WAVEINCAPSA wicA;
	wicA.wMid           = wicW.wMid;
	wicA.wPid           = wicW.wPid;
	wicA.vDriverVersion = wicW.vDriverVersion;
        WideCharToMultiByte( CP_ACP, 0, wicW.szPname, -1, wicA.szPname,
                             sizeof(wicA.szPname), NULL, NULL );
	wicA.dwFormats      = wicW.dwFormats;
	wicA.wChannels      = wicW.wChannels;
	memcpy(lpCaps, &wicA, min(uSize, sizeof(wicA)));
    }
    return ret;
}

/**************************************************************************
 * 				waveInOpen			[WINMM.@]
 */
MMRESULT WINAPI waveInOpen(HWAVEIN* lphWaveIn, UINT uDeviceID,
                           LPCWAVEFORMATEX lpFormat, DWORD_PTR dwCallback,
                           DWORD_PTR dwInstance, DWORD dwFlags)
{
    return WAVE_Open((HANDLE*)lphWaveIn, uDeviceID, MMDRV_WAVEIN, lpFormat,
                     dwCallback, dwInstance, dwFlags);
}

/**************************************************************************
 * 				waveInClose			[WINMM.@]
 */
UINT WINAPI waveInClose(HWAVEIN hWaveIn)
{
    LPWINE_MLD		wmld;
    DWORD		dwRet;

    TRACE("(%p)\n", hWaveIn);

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    dwRet = MMDRV_Message(wmld, WIDM_CLOSE, 0L, 0L);
    if (dwRet != WAVERR_STILLPLAYING)
	MMDRV_Free(hWaveIn, wmld);
    return dwRet;
}

/**************************************************************************
 * 				waveInPrepareHeader		[WINMM.@]
 */
UINT WINAPI waveInPrepareHeader(HWAVEIN hWaveIn, WAVEHDR* lpWaveInHdr,
				UINT uSize)
{
    LPWINE_MLD		wmld;
    UINT                result;

    TRACE("(%p, %p, %u);\n", hWaveIn, lpWaveInHdr, uSize);

    if (lpWaveInHdr == NULL || uSize < sizeof (WAVEHDR))
	return MMSYSERR_INVALPARAM;

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    if ((result = MMDRV_Message(wmld, WIDM_PREPARE, (DWORD_PTR)lpWaveInHdr,
                                uSize)) != MMSYSERR_NOTSUPPORTED)
        return result;

    if (lpWaveInHdr->dwFlags & WHDR_INQUEUE)
        return WAVERR_STILLPLAYING;

    lpWaveInHdr->dwFlags |= WHDR_PREPARED;
    lpWaveInHdr->dwFlags &= ~WHDR_DONE;
    lpWaveInHdr->dwBytesRecorded = 0;

    return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				waveInUnprepareHeader	[WINMM.@]
 */
UINT WINAPI waveInUnprepareHeader(HWAVEIN hWaveIn, WAVEHDR* lpWaveInHdr,
				  UINT uSize)
{
    LPWINE_MLD		wmld;
    UINT                result;

    TRACE("(%p, %p, %u);\n", hWaveIn, lpWaveInHdr, uSize);

    if (lpWaveInHdr == NULL || uSize < sizeof (WAVEHDR))
	return MMSYSERR_INVALPARAM;

    if (!(lpWaveInHdr->dwFlags & WHDR_PREPARED))
	return MMSYSERR_NOERROR;

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    if ((result = MMDRV_Message(wmld, WIDM_UNPREPARE, (DWORD_PTR)lpWaveInHdr,
                                uSize)) != MMSYSERR_NOTSUPPORTED)
        return result;

    if (lpWaveInHdr->dwFlags & WHDR_INQUEUE)
        return WAVERR_STILLPLAYING;

    lpWaveInHdr->dwFlags &= ~WHDR_PREPARED;
    lpWaveInHdr->dwFlags |= WHDR_DONE;

    return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				waveInAddBuffer		[WINMM.@]
 */
UINT WINAPI waveInAddBuffer(HWAVEIN hWaveIn,
			    WAVEHDR* lpWaveInHdr, UINT uSize)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p, %u);\n", hWaveIn, lpWaveInHdr, uSize);

    if (lpWaveInHdr == NULL) return MMSYSERR_INVALPARAM;
    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WIDM_ADDBUFFER, (DWORD_PTR)lpWaveInHdr, uSize);
}

/**************************************************************************
 * 				waveInReset		[WINMM.@]
 */
UINT WINAPI waveInReset(HWAVEIN hWaveIn)
{
    LPWINE_MLD		wmld;

    TRACE("(%p);\n", hWaveIn);

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WIDM_RESET, 0L, 0L);
}

/**************************************************************************
 * 				waveInStart		[WINMM.@]
 */
UINT WINAPI waveInStart(HWAVEIN hWaveIn)
{
    LPWINE_MLD		wmld;

    TRACE("(%p);\n", hWaveIn);

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WIDM_START, 0L, 0L);
}

/**************************************************************************
 * 				waveInStop		[WINMM.@]
 */
UINT WINAPI waveInStop(HWAVEIN hWaveIn)
{
    LPWINE_MLD		wmld;

    TRACE("(%p);\n", hWaveIn);

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld,WIDM_STOP, 0L, 0L);
}

/**************************************************************************
 * 				waveInGetPosition	[WINMM.@]
 */
UINT WINAPI waveInGetPosition(HWAVEIN hWaveIn, LPMMTIME lpTime,
			      UINT uSize)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p, %u);\n", hWaveIn, lpTime, uSize);

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    return MMDRV_Message(wmld, WIDM_GETPOS, (DWORD_PTR)lpTime, uSize);
}

/**************************************************************************
 * 				waveInGetID			[WINMM.@]
 */
UINT WINAPI waveInGetID(HWAVEIN hWaveIn, UINT* lpuDeviceID)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %p);\n", hWaveIn, lpuDeviceID);

    if (lpuDeviceID == NULL) return MMSYSERR_INVALHANDLE;

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL)
	return MMSYSERR_INVALHANDLE;

    *lpuDeviceID = wmld->uDeviceID;
    return MMSYSERR_NOERROR;
}

/**************************************************************************
 * 				waveInMessage 		[WINMM.@]
 */
UINT WINAPI waveInMessage(HWAVEIN hWaveIn, UINT uMessage,
                          DWORD_PTR dwParam1, DWORD_PTR dwParam2)
{
    LPWINE_MLD		wmld;

    TRACE("(%p, %u, %ld, %ld)\n", hWaveIn, uMessage, dwParam1, dwParam2);

    if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, FALSE)) == NULL) {
	if ((wmld = MMDRV_Get(hWaveIn, MMDRV_WAVEIN, TRUE)) != NULL) {
	    return MMDRV_PhysicalFeatures(wmld, uMessage, dwParam1, dwParam2);
	}
	return MMSYSERR_INVALHANDLE;
    }

    /* from M$ KB */
    if (uMessage < DRVM_IOCTL || (uMessage >= DRVM_IOCTL_LAST && uMessage < DRVM_MAPPER))
	return MMSYSERR_INVALPARAM;


    return MMDRV_Message(wmld, uMessage, dwParam1, dwParam2);
}
