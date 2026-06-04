@echo off
setlocal

set SRC=RiftByte.c
set CC=gcc
set WFLAGS=-O2 -Wno-unused-result
set RC=RiftByte.rc

set RES64=RiftByte_x64.res.o
set RES32=RiftByte_x32.res.o

echo.
echo RiftByte build script
echo =====================
echo.

if "%1"=="" goto all
if /i "%1"=="x64" goto win_x64
if /i "%1"=="x32" goto win_x32
if /i "%1"=="linux64" goto linux_x64
if /i "%1"=="linux32" goto linux_x32
if /i "%1"=="all" goto all

echo usage: build.bat [x64^|x32^|linux64^|linux32^|all]
goto end


:: =========================
:: ICONS
:: =========================
:icons
echo [*] Building icons...

windres --target=pe-x86-64 %RC% -O coff -o %RES64%
if errorlevel 1 (
    echo [FAIL] icon x64
    goto end
)

windres --target=pe-i386 %RC% -O coff -o %RES32%
if errorlevel 1 (
    echo [FAIL] icon x32
    goto end
)

goto :eof


:: =========================
:: WINDOWS
:: =========================

:win_x64
call :icons
echo [*] Windows x64...
%CC% -m64 -o RiftByte_x64.exe %SRC% %RES64%
if errorlevel 1 (echo [FAIL] x64) else (echo [OK] x64)
goto end


:win_x32
call :icons
echo [*] Windows x32...
%CC% -m32 -o RiftByte_x32.exe %SRC% %RES32%
if errorlevel 1 (echo [FAIL] x32) else (echo [OK] x32)
goto end


:: =========================
:: LINUX
:: =========================

:linux_x64
echo [*] Linux x64...
wsl gcc -o RiftByte_linux_x64 %SRC% %WFLAGS%
if errorlevel 1 (echo [FAIL] linux x64) else (echo [OK] linux x64)
goto end


:linux_x32
echo [*] Linux x32...
wsl bash -c "sudo apt-get install -y gcc-multilib > /dev/null 2>&1 && gcc -m32 -o RiftByte_linux_x32 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux x32) else (echo [OK] linux x32)
goto end


:: =========================
:: ALL
:: =========================

:all
echo [*] Building all targets...
echo.

call :icons

echo -- Windows --
%CC% -m64 -o RiftByte_x64.exe %SRC% %RES64%
if errorlevel 1 (echo [FAIL] x64) else (echo [OK] x64)

%CC% -m32 -o RiftByte_x32.exe %SRC% %RES32%
if errorlevel 1 (echo [FAIL] x32) else (echo [OK] x32)

echo.
echo -- Linux --
wsl gcc -o RiftByte_linux_x64 %SRC% %WFLAGS%
if errorlevel 1 (echo [FAIL] linux x64) else (echo [OK] linux x64)

wsl bash -c "sudo apt-get install -y gcc-multilib > /dev/null 2>&1 && gcc -m32 -o RiftByte_linux_x32 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux x32) else (echo [OK] linux x32)

echo.
echo Done.

:end
endlocal