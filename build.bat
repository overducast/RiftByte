@echo off
setlocal

set SRC=RiftByte.c
set TCC=tcc
set WFLAGS=-O2 -Wno-unused-result

echo.
echo  RiftByte build script
echo  =====================
echo.

if "%1"=="" goto all
if /i "%1"=="x64"         goto win_x64
if /i "%1"=="x32"         goto win_x32
if /i "%1"=="arm64"       goto win_arm64
if /i "%1"=="arm32"       goto win_arm32
if /i "%1"=="linux64"     goto linux_x64
if /i "%1"=="linux32"     goto linux_x32
if /i "%1"=="linux_arm64" goto linux_arm64
if /i "%1"=="linux_arm32" goto linux_arm32
if /i "%1"=="all"         goto all
echo usage: build.bat [x64^|x32^|arm64^|arm32^|linux64^|linux32^|linux_arm64^|linux_arm32^|all]
goto end

:win_x64
echo [*] Windows x64...
%TCC% -m64 -o RiftByte_x64.exe %SRC%
if errorlevel 1 (echo [FAIL] x64) else (echo [OK]   RiftByte_x64.exe)
goto end

:win_x32
echo [*] Windows x32...
%TCC% -m32 -o RiftByte_x32.exe %SRC%
if errorlevel 1 (echo [FAIL] x32) else (echo [OK]   RiftByte_x32.exe)
goto end

:win_arm64
echo [*] Windows ARM64...
%TCC% -march=arm64 -o RiftByte_arm64.exe %SRC%
if errorlevel 1 (echo [FAIL] arm64) else (echo [OK]   RiftByte_arm64.exe)
goto end

:win_arm32
echo [*] Windows ARM32...
%TCC% -march=arm -o RiftByte_arm32.exe %SRC%
if errorlevel 1 (echo [FAIL] arm32) else (echo [OK]   RiftByte_arm32.exe)
goto end

:linux_x64
echo [*] Linux x64...
wsl gcc -o RiftByte_linux_x64 %SRC% %WFLAGS%
if errorlevel 1 (echo [FAIL] linux x64) else (echo [OK]   RiftByte_linux_x64)
goto end

:linux_x32
echo [*] Linux x32...
wsl bash -c "sudo apt-get install -y gcc-multilib > /dev/null 2>&1 && gcc -m32 -o RiftByte_linux_x32 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux x32) else (echo [OK]   RiftByte_linux_x32)
goto end

:linux_arm64
echo [*] Linux ARM64...
wsl bash -c "sudo apt-get install -y gcc-aarch64-linux-gnu > /dev/null 2>&1 && aarch64-linux-gnu-gcc -o RiftByte_linux_arm64 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux arm64) else (echo [OK]   RiftByte_linux_arm64)
goto end

:linux_arm32
echo [*] Linux ARM32...
wsl bash -c "sudo apt-get install -y gcc-arm-linux-gnueabihf > /dev/null 2>&1 && arm-linux-gnueabihf-gcc -o RiftByte_linux_arm32 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux arm32) else (echo [OK]   RiftByte_linux_arm32)
goto end

:all
echo [*] Building all targets...
echo.

echo  -- Windows --
%TCC% -m64 -o RiftByte_x64.exe %SRC%
if errorlevel 1 (echo [FAIL] x64) else (echo [OK]   RiftByte_x64.exe)

gcc -m32 -o RiftByte_x32.exe %SRC%
if errorlevel 1 (echo [FAIL] x32) else (echo [OK]   RiftByte_x32.exe)

%TCC% -march=arm64 -o RiftByte_arm64.exe %SRC%
if errorlevel 1 (echo [FAIL] arm64) else (echo [OK]   RiftByte_arm64.exe)

%TCC% -march=arm -o RiftByte_arm32.exe %SRC%
if errorlevel 1 (echo [FAIL] arm32) else (echo [OK]   RiftByte_arm32.exe)

echo.
echo  -- Linux (via WSL) --
wsl gcc -o RiftByte_linux_x64 %SRC% %WFLAGS%
if errorlevel 1 (echo [FAIL] linux x64) else (echo [OK]   RiftByte_linux_x64)

wsl bash -c "sudo apt-get install -y gcc-multilib > /dev/null 2>&1 && gcc -m32 -o RiftByte_linux_x32 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux x32) else (echo [OK]   RiftByte_linux_x32)

echo.
echo  -- Linux ARM (via WSL) --
wsl bash -c "sudo apt-get install -y gcc-aarch64-linux-gnu > /dev/null 2>&1 && aarch64-linux-gnu-gcc -o RiftByte_linux_arm64 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux arm64) else (echo [OK]   RiftByte_linux_arm64)

wsl bash -c "sudo apt-get install -y gcc-arm-linux-gnueabihf > /dev/null 2>&1 && arm-linux-gnueabihf-gcc -o RiftByte_linux_arm32 %SRC% %WFLAGS%"
if errorlevel 1 (echo [FAIL] linux arm32) else (echo [OK]   RiftByte_linux_arm32)

echo.
echo Done.

:end
endlocal