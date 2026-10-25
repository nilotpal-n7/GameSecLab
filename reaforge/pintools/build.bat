@echo off
REM Build a REAForge pintool via Pin's own make (the pin-clang-cl++/pin-ld wrappers are bash
REM scripts, so we drive `make` under msys, not cmd directly). Source stays here in the repo;
REM we stage it into a Pin tool dir, build, and copy the .dll back.
REM Usage:  build.bat recon_trace.cpp   ->  recon_trace.dll in this folder
setlocal
set PIN=C:\Tools\PIN\pin-external-4.4-99977-g54fbb8814-clang-windows
set TOOLDIR=%PIN%\source\tools\REAForge
set SRCDIR=%~dp0
set NAME=%~n1
set FILE=%~nx1
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set PATH=C:\Tools\ollvm\install\bin;C:\Tools\msys64\usr\bin;%PATH%
if not exist "%TOOLDIR%" mkdir "%TOOLDIR%"
copy /y "%PIN%\source\tools\MyPinTool\makefile" "%TOOLDIR%\makefile" >nul
> "%TOOLDIR%\makefile.rules" echo TEST_TOOL_ROOTS := %NAME%
>> "%TOOLDIR%\makefile.rules" echo TEST_ROOTS :=
>> "%TOOLDIR%\makefile.rules" echo TOOL_ROOTS :=
>> "%TOOLDIR%\makefile.rules" echo SA_TOOL_ROOTS :=
>> "%TOOLDIR%\makefile.rules" echo APP_ROOTS :=
>> "%TOOLDIR%\makefile.rules" echo OBJECT_ROOTS :=
>> "%TOOLDIR%\makefile.rules" echo DLL_ROOTS :=
>> "%TOOLDIR%\makefile.rules" echo LIB_ROOTS :=
copy /y "%SRCDIR%%FILE%" "%TOOLDIR%\%FILE%" >nul
cd /d "%TOOLDIR%"
make TARGET=intel64 obj-intel64/%NAME%.dll 2>&1 | findstr /v /c:"/bin/sh"
if not exist "%TOOLDIR%\obj-intel64\%NAME%.dll" ( echo BUILD FAILED & exit /b 1 )
copy /y "%TOOLDIR%\obj-intel64\%NAME%.dll" "%SRCDIR%%NAME%.dll" >nul
echo === built %NAME%.dll ===
