/* sip_report_tool.c — tiny diagnostic: load sip_progate.dll and print this machine's HWID and the DLL's
 * on-disk image CRC-32 (whole file; "text_crc" in the format), the two values needed to issue a license
 * for this exact build:
 *
 *     python license_signer.py issue --hwid <HWID> --text-crc 0x<CRC> --subject "Name" --tier pro
 *
 * Build + run it from the folder that holds the SAME sip_progate.dll System Informer loads (bin\Release64),
 * so the CRC matches what the gate computes at runtime:
 *
 *     cl /nologo /O2 sip_report_tool.c
 *     copy sip_report_tool.exe <...>\bin\Release64\  &  cd /d <...>\bin\Release64  &  sip_report_tool.exe
 */
#include <stdio.h>
#include <windows.h>

typedef void (*sip_report_fn)(char *hwid_out, int hwid_cap, unsigned int *crc_out);
typedef int (*sip_gate_init_fn)(const char *path);
typedef int (*sip_is_pro_fn)(void);
typedef unsigned int (*sip_access_mask_fn)(int feature);

/* With no argument: print HWID + .text CRC (to issue a license).
 * With a .sipm path:  run the gate against it and print the verified tier + the dump ACCESS_MASK,
 *                     proving the C++ verifier agrees with license_signer.py. */
int main(int argc, char **argv) {
	HMODULE h = LoadLibraryW(L"sip_progate.dll");
	if (!h) {
		printf("LoadLibrary(sip_progate.dll) failed: %lu (run from the folder holding the DLL)\n",
		       GetLastError());
		return 1;
	}
	sip_report_fn report = (sip_report_fn)GetProcAddress(h, "sip_report");
	char hwid[512] = {0};
	unsigned int crc = 0;
	if (report) {
		report(hwid, (int)sizeof(hwid), &crc);
		printf("HWID=%s\n", hwid);
		printf("TEXT_CRC=0x%08X\n", crc);
	}

	if (argc > 1) {
		sip_gate_init_fn gate_init = (sip_gate_init_fn)GetProcAddress(h, "sip_gate_init");
		sip_is_pro_fn is_pro = (sip_is_pro_fn)GetProcAddress(h, "sip_is_pro");
		sip_access_mask_fn mask = (sip_access_mask_fn)GetProcAddress(h, "sip_access_mask");
		if (!gate_init || !is_pro || !mask) {
			printf("gate exports missing\n");
			return 1;
		}
		int rc = gate_init(argv[1]);
		printf(
		    "\nsip_gate_init(\"%s\") = %d  (0=OK,1=no-license,2=badfmt,3=sig,4=KDF,5=expired,6=slug,7=dbg)\n",
		    argv[1], rc);
		printf("sip_is_pro = %d\n", is_pro());
		printf("sip_access_mask(DUMP) = 0x%04X   (0x0450 = licensed, 0x1000 = unlicensed trap)\n",
		       mask(0 /*SIP_FEAT_DUMP*/));
	}
	return 0;
}
