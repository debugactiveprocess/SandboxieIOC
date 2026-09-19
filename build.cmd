@echo off
REM Build SandboxieIOC with the MinGW Qt kit.
REM QSbieAPI sources are compiled into the executable (static ABI-compatible build).
setlocal

set "QTDIR=C:\Qt\6.11.2\mingw_64"
set "MINGW=C:\Qt\Tools\mingw1310_64\bin"

set "PATH=%QTDIR%\bin;%MINGW%;%PATH%"

cd /d "%~dp0"
if not exist build-mingw mkdir build-mingw
cd build-mingw

"%QTDIR%\bin\qmake.exe" ..\SandboxieIOC.pro "CONFIG+=release" || goto :err
"%MINGW%\mingw32-make.exe" -f Makefile.Release -j8 || goto :err

echo.
echo Build OK: %~dp0build-mingw\release\SandboxieIOC.exe
goto :eof

:err
echo Build failed
exit /b 1


