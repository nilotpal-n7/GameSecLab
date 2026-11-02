@echo off
REM Build sip_progate.dll — the System Informer Pro licensing core.
REM /MD (to match the prebuilt licenseseat.lib), /Zi /DEBUG /MAP so the VMProtect pass resolves markers.
REM Output: an import lib (sip_progate.lib) + sip_progate.dll + .map, which SI (/MT) links over the C ABI.
REM
REM Usage:  build_sip_progate.cmd [out_dir]
REM   out_dir default = C:\Tools\GameSecLab\demo\systeminformer\sip\bin

setlocal
set "REPO=C:\Tools\GameSecLab"
set "SRC=%REPO%\targets\system_informer\src"
set "LS=%REPO%\demo\licenseseat"
set "VMP=C:\Program Files\VMProtect Demo"
REM licenseseat.lib depends on OpenSSL (EVP_* in crypto.obj) + advapi32 (Reg* in device.obj).
REM Use the /MD release import libs to match this DLL's CRT.
set "OSSL=C:\Program Files\OpenSSL-Win64\lib\VC"
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%REPO%\demo\systeminformer\sip\bin"
set "OBJ=%OUT%\obj"

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul || (echo vcvars FAILED & exit /b 1)
if not exist "%OBJ%" mkdir "%OBJ%"

echo [1/2] compiling...
REM /DDEMO_SOFT = filmable demo (anti-tamper logs instead of corrupting). Drop it for the "hard" build.
cl /c /nologo /std:c++17 /EHsc /MD /O2 /Zi /DDEMO_SOFT ^
  /I"%LS%\include" /I"%VMP%\Include\C" ^
  /Fo"%OBJ%\\" /Fd"%OBJ%\vc.pdb" ^
  "%SRC%\pro_gate.cpp" "%SRC%\sip_crypto_licenseseat.cpp" || (echo COMPILE FAILED & exit /b 1)

echo [2/2] linking DLL...
link /DLL /nologo /DEBUG /MAP ^
  /DEF:"%SRC%\sip_progate.def" ^
  /OUT:"%OUT%\sip_progate.dll" ^
  "%OBJ%\pro_gate.obj" "%OBJ%\sip_crypto_licenseseat.obj" ^
  "%LS%\lib\licenseseat.lib" ^
  "%VMP%\Lib\Windows\VMProtectSDK64.lib" ^
  "%OSSL%\libcrypto64MD.lib" ^
  bcrypt.lib advapi32.lib crypt32.lib ws2_32.lib user32.lib || (echo LINK FAILED & exit /b 1)

echo BUILD_OK: "%OUT%\sip_progate.dll"
endlocal
