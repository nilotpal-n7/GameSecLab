/* sip_delayload.c -- delay-load resolver for sip_progate.dll.
 *
 * System Informer hardens its DLL search: SystemInformer.exe is linked with DependentLoadFlags =
 * LOAD_LIBRARY_SEARCH_SYSTEM32 (0x0800), and plugins are loaded with LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
 * LOAD_LIBRARY_SEARCH_SYSTEM32. Neither search includes the application directory, so a statically- (or
 * plainly delay-) imported sip_progate.dll sitting next to SystemInformer.exe is reported "not found"
 * (STATUS_DLL_NOT_FOUND / 0xC0000135) and the host or plugin fails to load.
 *
 * Fix: sip_progate.dll is delay-loaded, and this hook resolves it by FULL PATH from the host executable's
 * own directory, with LOAD_WITH_ALTERED_SEARCH_PATH so sip_progate's own dependency (libcrypto-1_1-x64.dll,
 * also app-local) resolves from that same folder. Compiled into BOTH SystemInformer.exe and
 * ExtendedTools.dll; each image gets its own delay-load hook (no shared/duplicate symbol).
 *
 * Only sip_progate.dll is special-cased; every other delay-load falls through to the default helper.
 */
#include <windows.h>
#include <delayimp.h>
#include <string.h>

static FARPROC WINAPI SipDelayHook(unsigned dliNotify, PDelayLoadInfo pdli)
{
    if (dliNotify == dliNotePreLoadLibrary && pdli && pdli->szDll &&
        _stricmp(pdli->szDll, "sip_progate.dll") == 0)
    {
        WCHAR path[MAX_PATH];
        DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH); /* host process image (SystemInformer.exe) */

        if (n != 0 && n < MAX_PATH)
        {
            WCHAR *slash = wcsrchr(path, L'\\');
            if (slash)
            {
                size_t room = (size_t)(MAX_PATH - (slash + 1 - path));
                if (wcslen(L"sip_progate.dll") < room)
                {
                    HMODULE module;
                    wcscpy_s(slash + 1, room, L"sip_progate.dll");
                    if (module = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH))
                        return (FARPROC)module; /* the helper uses this as the resolved HMODULE */
                }
            }
        }
    }

    return NULL; /* fall through to the default delay-load behaviour */
}

const PfnDliHook __pfnDliNotifyHook2 = SipDelayHook;
