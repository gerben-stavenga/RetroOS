@echo off
REM Game: Bio Menace 1.1 (Freeware release)
REM Configuration: standard
REM 
config -set render aspect=true
cls
if exist BMENACE\BIOPATCH.EXE goto run
echo Setting up game files, please wait...
unzip32 -qq bmfreew.zip -d BMENACE\
unzip32 -qq BMENACE\BIOPATCH.zip -d BMENACE\
unzip32 -qq bmlnch.zip -d BMENACE\
:run
config -set cpu "cycles=auto 6075 98%% limit 23880"
cd BMENACE
cls
BIOPATCH.EXE
CALL BMENACE.BAT
cd..
cls
echo Thank you for playing Bio Menace!
echo.
echo To play again, type BMENACE and press Enter
echo.
echo Your DOS Games Archive http://www.dosgamesarchive.com/
@echo on