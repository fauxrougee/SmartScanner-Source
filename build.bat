@echo off
REM SmartScanner Build Script
REM Run from Visual Studio Developer Command Prompt

setlocal

REM Find Qt path
set QT_PATH=
for %%P in (
    "C:\Qt\6.8.3\msvc2022_64"
    "C:\Qt\6.7.2\msvc2022_64"
    "%USERPROFILE%\Qt\6.8.3\msvc2022_64"
) do (
    if exist "%%~P\bin\qmake.exe" set QT_PATH=%%~P
)

if "%QT_PATH%"=="" (
    echo ERROR: Qt not found. Set QT_PATH manually.
    exit /b 1
)

echo Using Qt: %QT_PATH%
set CMAKE_PREFIX_PATH=%QT_PATH%
set PATH=%QT_PATH%\bin;%PATH%

REM Create build directory
if not exist build mkdir build
cd build

REM Configure and build
echo.
echo Configuring...
cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 (
    echo CMake configuration failed
    exit /b 1
)

echo.
echo Building...
cmake --build . --config Release
if errorlevel 1 (
    echo Build failed
    exit /b 1
)

echo.
echo === BUILD SUCCESSFUL ===
dir /b *.exe
echo.
echo Executables are in: %CD%
