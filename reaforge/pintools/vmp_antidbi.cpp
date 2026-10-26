// vmp_antidbi — anti-anti-DBI pintool: emulate the single-step (#DB) exception that a real
// CPU raises when the Trap Flag is set, but which Pin's JIT does NOT deliver. VMProtect's
// anti-DBI relies on that exception reaching its own handler; under plain Pin it never fires,
// so VMProtect detects the instrumentation and kills the process. We re-synthesize it.
//
// Method (matches the DBI-bypass literature, e.g. Polino/D'Elia; API pattern from sok-dbi-security):
//   real HW: an instruction that executes with TF=1 is followed by #DB (EIP -> next instr), TF auto-cleared.
//   so, before instruction X: if the PREVIOUS instruction ran with TF set -> raise #DB now (addr = X);
//       else if TF is set now -> arm (X will run with TF, trap comes after it).
//   PIN_RaiseException delivers the exception to the app's VEH/SEH on return from the analysis routine.
//
// Authorized targets only (our own license_app.vmp.exe).
#include "pin.H"
#include <fstream>

#define TF_BIT 0x100
#define MAXTH  256

static bool armed[MAXTH] = { false };
static std::ofstream out;
static UINT64 ndb = 0, nctx = 0, icount = 0, nextMark = 50000000;

KNOB<std::string> KnobOut(KNOB_MODE_WRITEONCE, "pintool", "o", "vmp_antidbi.log", "output file");

static VOID cIns() { if (++icount >= nextMark) { out << "progress icount=" << icount << " db=" << ndb << "\n"; out.flush(); nextMark += 50000000; } }

// fast predicate: do we need the heavy path on this instruction?
static ADDRINT needStep(ADDRINT flags, THREADID tid) {
    return (tid < MAXTH) && (armed[tid] || (flags & TF_BIT));
}

// heavy path: arm, or deliver the single-step exception
static VOID ssStep(ADDRINT eip, ADDRINT flags, THREADID tid, CONTEXT *ctx) {
    if (tid >= MAXTH) return;
    if (armed[tid]) {
        armed[tid] = false;
        PIN_SetContextReg(ctx, REG_GFLAGS, flags & ~(ADDRINT)TF_BIT); // #DB clears TF
        EXCEPTION_INFO exc;
        PIN_InitWindowsExceptionInfo(&exc, 0x80000004 /* EXCEPTION_SINGLE_STEP */, eip);
        ndb++;
        PIN_RaiseException(ctx, tid, &exc); // delivered to the app on return
        return;
    }
    if (flags & TF_BIT) armed[tid] = true;
}

static VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)cIns, IARG_END);
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)needStep,
                     IARG_REG_VALUE, REG_GFLAGS, IARG_THREAD_ID, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ssStep,
                       IARG_INST_PTR, IARG_REG_VALUE, REG_GFLAGS, IARG_THREAD_ID, IARG_CONTEXT, IARG_END);
}

static VOID OnCtxChange(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT *from,
                        CONTEXT *to, INT32 info, VOID *v) {
    nctx++;
    if (nctx <= 40) { out << "[CTXCHG] reason=" << reason << " info=0x" << std::hex << info
                          << std::dec << " icount=" << icount << "\n"; out.flush(); }
}

static VOID Fini(INT32 code, VOID *v) {
    out << "[FINI] code=" << code << " icount=" << icount << " db_delivered=" << ndb
        << " ctxchg=" << nctx << "\n";
    out.flush(); out.close();
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;
    out.open(KnobOut.Value().c_str());
    out << "# vmp_antidbi start (single-step emulation)\n"; out.flush();
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddContextChangeFunction(OnCtxChange, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
