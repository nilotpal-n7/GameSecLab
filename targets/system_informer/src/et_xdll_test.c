/* et_xdll_test.c — standalone proof of the cross-DLL handshake, the ExtendedTools analogue of
 * sip_report_tool. It links et_xdll.c directly (NOT the full ExtendedTools.dll, which imports from
 * SystemInformer.exe and so cannot load standalone) plus sip_progate.lib, so it exercises the real
 * challenger -> sip_progate responder -> response-as-key unlock path end to end.
 *
 * Run it from the folder holding sip_progate.dll + the .sipm (bin\Release64):
 *     cl /nologo et_xdll_test.c et_xdll.c /I. /link <...>\sip_progate.lib
 *     copy et_xdll_test.exe <...>\bin\Release64\  &  cd /d <...>\bin\Release64  &  et_xdll_test.exe SystemInformer.sipm
 */
#include <windows.h>
#include <stdio.h>
#include "pro_gate.h"
#include "et_xdll.h"

int main(int argc, char **argv)
{
    const char *sipm = (argc > 1) ? argv[1] : "SystemInformer.sipm";

    /* The host (SystemInformer.exe) normally does this; we do it so sip_progate caches the Pro state +
     * xdll_seed that the handshake response is derived from. */
    int rc = sip_gate_init(sipm);
    int flags = EtXdllUnlock(sipm);

    printf("sip_gate_init(\"%s\") = %d  (0 = OK Pro)\n", sipm, rc);
    printf("sip_is_pro               = %d\n", sip_is_pro());
    printf("EtXdllUnlock flags       = %d  (1 = Pro unlocked via handshake, 0 = Community/denied)\n", flags);
    printf("EtIsProUnlocked          = %d\n", EtIsProUnlocked());
    return flags ? 0 : 2;
}
