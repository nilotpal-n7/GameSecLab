// vmp_probe — diagnostic pintool: how far does the protected binary get under Pin, and how
// does it die? Uses Pin's syscall + context-change callbacks (catch direct syscalls and
// exceptions, incl. the single-step exception VMProtect's anti-DBI relies on).
// Authorized targets only.
#include "pin.H"
#include <fstream>

static std::ofstream out;
static UINT64 icount = 0, npopf = 0, nrdtsc = 0, ncpuid = 0, nsys = 0;
static UINT64 nextMark = 500000;

KNOB<std::string> KnobOut(KNOB_MODE_WRITEONCE, "pintool", "o", "vmp_probe.log", "output file");

static VOID cIns() {
    if (++icount >= nextMark) { out << "progress icount=" << icount << "\n"; out.flush(); nextMark += 500000; }
}
static VOID cPopf()  { npopf++;  }
static VOID cRdtsc() { nrdtsc++; }
static VOID cCpuid() { ncpuid++; }

static VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)cIns, IARG_END);
    switch (INS_Opcode(ins)) {
        case XED_ICLASS_POPF: case XED_ICLASS_POPFD: case XED_ICLASS_POPFQ:
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)cPopf, IARG_END); break;
        case XED_ICLASS_RDTSC: case XED_ICLASS_RDTSCP:
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)cRdtsc, IARG_END); break;
        case XED_ICLASS_CPUID:
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)cCpuid, IARG_END); break;
        default: break;
    }
}

// every syscall (including inlined `syscall` instructions) — the terminator shows up here
static VOID SysEnter(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v) {
    ADDRINT num = PIN_GetSyscallNumber(ctxt, std);
    nsys++;
    out << "SYS num=0x" << std::hex << num << std::dec << " icount=" << icount << "\n";
    out.flush();
}

// exceptions / signals / aborts — single-step exception (0x80000004) would appear here
static VOID OnCtxChange(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from,
                        CONTEXT *to, INT32 info, VOID *v) {
    out << "[CTXCHG] reason=" << reason << " info=0x" << std::hex << info << std::dec
        << " icount=" << icount << "\n";
    out.flush();
}

static VOID Fini(INT32 code, VOID *v) {
    out << "[FINI] code=" << code << " icount=" << icount << " popf=" << npopf
        << " rdtsc=" << nrdtsc << " cpuid=" << ncpuid << " sys=" << nsys << "\n";
    out.flush();
    out.close();
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;
    out.open(KnobOut.Value().c_str());
    out << "# vmp_probe start\n"; out.flush();
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddSyscallEntryFunction(SysEnter, 0);
    PIN_AddContextChangeFunction(OnCtxChange, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
