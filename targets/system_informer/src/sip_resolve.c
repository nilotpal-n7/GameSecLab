/* sip_resolve.c -- robust explicit-load shim for sip_progate.dll.
 *
 * System Informer hardens its DLL search (DependentLoadFlags = LOAD_LIBRARY_SEARCH_SYSTEM32, and plugins
 * load with DLL_LOAD_DIR|SYSTEM32), so neither a static nor a plain delay-load of the app-local
 * sip_progate.dll can be resolved by the loader -- it reports STATUS_DLL_NOT_FOUND (0xC0000135) at image
 * load, and a failed delay-load raises an unhandled exception at the call site (access violation).
 *
 * This file DEFINES the four sip_* entry points the host and plugin call (see pro_gate.h) as thin wrappers
 * that load sip_progate.dll ONCE, by FULL PATH, from the host executable's own directory
 * (LOAD_WITH_ALTERED_SEARCH_PATH so sip_progate's app-local libcrypto dependency also resolves), then
 * forward through GetProcAddress. Link this object instead of importing sip_progate.lib: there is then NO
 * static or delay import of sip_progate anywhere, so SystemInformer.exe and ExtendedTools.dll load cleanly
 * regardless of the hardened search, and a missing/unloadable core fails SAFE (trap mask / not-Pro) rather
 * than crashing. Compiled into both SystemInformer.exe and ExtendedTools.dll (each keeps its own handle).
 */
#include <windows.h>
#include <string.h>
#include "pro_gate.h"

static HMODULE SipProgateModule(void)
{
    static HMODULE module = NULL;

    if (!module)
    {
        WCHAR path[MAX_PATH];
        DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH); /* host image (SystemInformer.exe) */

        if (length != 0 && length < MAX_PATH)
        {
            WCHAR *slash = wcsrchr(path, L'\\');

            if (slash && (MAX_PATH - (slash + 1 - path)) > 16)
            {
                wcscpy_s(slash + 1, MAX_PATH - (slash + 1 - path), L"sip_progate.dll");
                module = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
            }
        }
    }

    return module;
}

SipInitResult sip_gate_init(const char *machine_file_path)
{
    typedef SipInitResult (*InitFn)(const char *);
    HMODULE module = SipProgateModule();
    char buffer[MAX_PATH];
    InitFn function;

    if (!module)
        return SIP_NO_LICENSE;

    /* NULL -> the .sipm beside the executable (not the process CWD, which is unreliable for a GUI app). */
    if (!machine_file_path)
    {
        DWORD length = GetModuleFileNameA(NULL, buffer, MAX_PATH);

        if (length != 0 && length < MAX_PATH)
        {
            char *slash = strrchr(buffer, '\\');

            if (slash && (MAX_PATH - (slash + 1 - buffer)) > 20)
            {
                strcpy_s(slash + 1, MAX_PATH - (slash + 1 - buffer), "SystemInformer.sipm");
                machine_file_path = buffer;
            }
        }
    }

    function = (InitFn)GetProcAddress(module, "sip_gate_init");
    return function ? function(machine_file_path) : SIP_NO_LICENSE;
}

int sip_is_pro(void)
{
    typedef int (*IsProFn)(void);
    HMODULE module = SipProgateModule();
    IsProFn function = module ? (IsProFn)GetProcAddress(module, "sip_is_pro") : NULL;

    return function ? function() : 0;
}

ACCESS_MASK sip_access_mask(int feature)
{
    typedef ACCESS_MASK (*MaskFn)(int);
    HMODULE module = SipProgateModule();
    MaskFn function = module ? (MaskFn)GetProcAddress(module, "sip_access_mask") : NULL;

    /* Fail safe: the unlicensed trap mask (handle opens, the privileged operation is denied). */
    return function ? function(feature) : (ACCESS_MASK)0x1000;
}

int sip_xdll_respond(const unsigned char challenge[32], unsigned char response_out[32])
{
    typedef int (*RespondFn)(const unsigned char *, unsigned char *);
    HMODULE module = SipProgateModule();
    RespondFn function = module ? (RespondFn)GetProcAddress(module, "sip_xdll_respond") : NULL;

    return function ? function(challenge, response_out) : 0;
}
