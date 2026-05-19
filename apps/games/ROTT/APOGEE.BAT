@echo off
if "%1"=="1" goto unpack

:message
echo.
echo This batch file is a remnant of having installed an Apogee game
echo on your hard drive.  It serves no other purpose, and may be deleted.
echo Deleting this batch file will not affect your game whatsoever.
echo.
echo -- Apogee Technical Support
echo.
goto end

:unpack
rott13sb.exe
if exist rott13sb.exe del rott13sb.exe
goto end

:end
