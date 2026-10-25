// recon_trace — a starter Intel Pin tool for the REAForge lab.
//
// Authorized use only: run this against binaries you own or are explicitly authorized to
// analyze (your own license_app.exe, CTF/crackme samples, owned games you may mod).
//
// What it does (maps to capstone C5 step 3 — "find the checks"):
//   * counts every executed instruction (DBI overhead / coverage baseline), and
//   * logs the runtime address of every CPUID / RDTSC / RDTSCP executed.
// Those instructions are the ones a VM-protector must execute NATIVELY (they full-exit the
// VM), so they are reliable anchors for locating hardware-fingerprint and timing checks —
// including ones in JIT'd/heap code that static analysis never sees.
//
// Build + run: see phases/pin_lab.md.

#include "pin.H"
#include <fstream>
#include <iostream>

static UINT64 icount = 0;
static UINT64 special = 0;
static std::ofstream out;

KNOB<std::string> KnobOut(KNOB_MODE_WRITEONCE, "pintool", "o", "recon_trace.log",
                          "output file for the special-instruction trace");

static VOID CountIns() { icount++; }

// addr + a static string literal (safe to pass as IARG_PTR: it has static storage).
static VOID LogSpecial(ADDRINT addr, const char *mnemonic) {
    special++;
    out << mnemonic << " @ 0x" << std::hex << addr << std::dec << "\n";
}

static VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CountIns, IARG_END);

    const char *mn = nullptr;
    switch (INS_Opcode(ins)) {
        case XED_ICLASS_CPUID:  mn = "cpuid";  break;
        case XED_ICLASS_RDTSC:  mn = "rdtsc";  break;
        case XED_ICLASS_RDTSCP: mn = "rdtscp"; break;
        default: break;
    }
    if (mn) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogSpecial,
                       IARG_INST_PTR, IARG_PTR, mn, IARG_END);
    }
}

static VOID Fini(INT32 code, VOID *v) {
    out << "# instructions executed: " << icount << "\n";
    out << "# cpuid/rdtsc(p) executed: " << special << "\n";
    out.close();
    std::cerr << "[recon_trace] " << icount << " instrs, " << special
              << " cpuid/rdtsc(p) -> " << KnobOut.Value() << "\n";
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        std::cerr << "recon_trace: a Pin tool. Usage:\n"
                  << "  pin -t recon_trace.dll [-o out.log] -- <target.exe> [args]\n";
        return 1;
    }
    out.open(KnobOut.Value().c_str());
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram(); // never returns
    return 0;
}
