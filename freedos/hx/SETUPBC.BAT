@ECHO OFF
REM Configure BCC environment for FreeDOS testing — apps live on D: not C:
SET PATH=D:\BORLANDC\BIN;D:\TC;%PATH%
SET INCLUDE=D:\BORLANDC\INCLUDE
SET LIB=D:\BORLANDC\LIB
ECHO BCC environment set. Try:
ECHO   HDPMI16        REM load Japheth DPMI host
ECHO   BCC -mt -lt D:\SRC\COMMAND.C   REM compile via BCC + TC TLINK
