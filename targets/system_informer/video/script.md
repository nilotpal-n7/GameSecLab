# Breaking System Informer Pro — walkthrough script

**Target length:** ~20 min · **Format:** screen-first, no face, voiceover · **Voice:** your own (record in short
passes; retakes are invisible on a screen cut).

**How to read this file**
- Plain text = narration, spoken.
- `[ ... ]` = delivery / emotion cue (how to say it, when to pause).
- **[Screen: ...]** = what's on screen at that moment.
- **[ANIM: name]** = cut to a motion-graphic beat. Beats live in `reaforge/viz/`. Status: `mask` = built
  (`branchless_mask.py`), the rest to build from the same kit.
- `~m:ss` markers are rough targets at ~140 words/min — don't chase them, they're just pacing rails.

**Recording tips baked into the cut**
- Read off a second monitor; mark your breaths at the line breaks.
- The emotion that sells this isn't acted — it's you *reacting* to the content. The two beats that carry the
  whole video are the patch that does nothing (§0) and the Frida mystery (§5). Perform those, don't read them.
- Capture every terminal/UI take at 1440p+, font 18–20pt, a clean desktop, one accent color. The commands are
  already one-liners (that's why) — do a dry run so each take is a clean single take.

---

## §0 — Cold open  ~0:00–1:00

**[Screen: System Informer open, a busy process list. Right-click a process → the "System Informer Pro"
submenu — Dump, Inject, Edit — all greyed out.]**

This is System Informer. Think Task Manager — for people who actually want to know what their machine is
doing. And these three options right here —

**[Screen: hover the greyed items; click one, nothing happens.]**

— are locked. Pro features. Licensed.

[beat]

Now normally? This is the easiest thing in the world. You open a debugger, you find the check — some
`if (licensed)`, somewhere — you flip one jump, and you're done. Five minutes. I've done it a hundred times.

**[Screen: x64dbg attached, scrolling, land on a plausible compare + conditional jump near the menu handler.
Patch the jump — nop it / invert it. Save.]**

So I did exactly that.

**[Screen: back in SI, right-click, click the Pro item again — still greyed / still dead.]**

And… [flat] nothing.

[a little incredulous] I patched the check. The feature's still dead.

[quicker, leaning in] Because there *is* no check. Not the way you think.

**[ANIM: mask — open on the formula, hold.]**

The license on this thing isn't a yes or a no. It's wired — directly — into the memory access the tool asks
the *kernel* for. There's no branch to flip. Nothing to patch.

[beat] And that's the moment I knew this was gonna take a while.

**[Title card: "Breaking System Informer Pro — two protectors, one license."]**

---

## §1 — The setup  ~1:00–3:00

**[Screen: SI running, calm b-roll of the UI — process tree, graphs.]**

Okay. Let's back up and do this properly.

System Informer is open source — it's the community successor to Process Hacker. What I'm running is a
*fork*: same tool, but somebody bolted a commercial "Pro" tier on top. Three features, all gated:

**[Screen: the Pro submenu again, naming each as it's highlighted.]**

A process **memory dumper** — snapshot a running process to disk. A **DLL injector**. And a live **memory
editor** — read and write another process's memory by hand. Serious, powerful stuff. Exactly the kind of
thing you'd put behind a license.

[curious] And here's what makes it interesting. When you buy the Pro tier, you don't get a new build. You get
a *file* — a little machine-bound license that sits next to the executable. The features were in there the
whole time. The license just… decides whether they work.

So the obvious question: how does it decide? And *that* is where this stops being a normal crackme.

**[ANIM: mask — full beat, ~35s, let it play with narration under it.]**

Every one of those features ends up calling into the kernel to open a process — `NtOpenProcess` — and that
call takes an *access mask*: a bitfield that says exactly what you're allowed to do to that process. Dump
needs read rights. Inject needs to allocate and write. The editor needs write.

What this gate does is take three facts — are you *entitled*, does the binary's *checksum* match, is there
*no debugger* — AND them into a single bit. Then it does something clever: it *negates* that bit into a
full-width mask. One becomes all-ones. Zero becomes all-zeros.

**[ANIM: mask — the select moment.]**

And then the access mask is just: `base AND m`, OR'd with a trap value AND *not*-m. Licensed, and the real
access rights survive. Not licensed —

**[ANIM: mask — the flip to trap.]**

— and you get the trap mask instead. `0x1000`. The handle still opens. It looks like it worked. But the
operation quietly dies, because you were never granted the right to do it.

[flat, dry] No compare. No jump. Nothing to NOP. The license value *is* the access mask.

[beat] This wasn't a weekend project.

---

## §2 — Recon: two protectors  ~3:00–5:30

**[Screen: terminal. Run the reaforge orchestrator recon step; DIE (Detect It Easy) output scrolls.]**

First thing you do with an unknown binary is ask what it's made of. This is Detect It Easy, driven from my
toolchain. And right away —

**[Screen: DIE flags the core module.]**

— the core. **VMProtect.** Then I point it at the plugin that carries the feature menu —

**[Screen: DIE on the plugin → Themida / WinLicense.]**

— and that one's **Themida**. [small laugh] Two different commercial protectors. In one target. Great.

Quick primer, because this matters for everything after.

**[ANIM: protectors — a clean binary, then two transforms.]**

A protector wraps your real code so it's hard to read and hard to run outside the licensed environment.
There are two big families here. **Packing** encrypts your code and unrolls it in memory at runtime — so on
disk there's nothing to read. **Virtualization** is nastier: it takes your actual instructions and rewrites
them into bytecode for a *made-up* CPU that only exists inside the protector. Your logic is still there — but
to read it, you'd have to reverse the imaginary processor first.

VMProtect does both. Themida does both, plus a specialty we'll get to that makes the imports lie to you.

[matter-of-fact] So there's no single "unpack" button. Two protectors, two completely different jobs.

---

## §3 — Breaking VMProtect  ~5:30–10:00

**[Screen: terminal, the unpack step starting.]**

Let's take the core first — the VMProtect side, because that's where the gate logic lives.

You can't just read the packed file; on disk the real code is encrypted. So instead of fighting the unpacker,
I let it do its job — under emulation. My toolchain loads the packed binary into a CPU emulator and *runs* it,
step by step, until it finishes decrypting itself and jumps to the original entry point — the OEP.

**[ANIM: unpack — packed bytes resolving toward an OEP marker.]**

**[Screen: the emulator reaching OEP; a snapshot being written.]**

The moment it hits that point, I freeze it. Snapshot the whole memory image. Now I've got the *real*,
decrypted code sitting in a file — and every future run starts from this snapshot instead of unpacking again.
[aside] Minutes, down to seconds.

**[Screen: IDA Pro opens on the snapshot. Navigate to the gate export.]**

Now, IDA. This is the function the whole gate rides on — the one that produces that access mask. And here's
what's waiting for me.

**[Screen: the export body — a tiny stub: move a register, load an address, jump.]**

[beat] That's it. Move a value, load a pointer, jump. That's not the function. That's a *doorway* — into the
virtual machine. The real logic was turned into bytecode for that made-up CPU I mentioned. Watch what happens
when I ask IDA's decompiler for the C.

**[Screen: Hex-Rays bails / produces nothing meaningful.]**

Nothing. [small, satisfied] And that's not a failure — that *is* the evidence. A normal function decompiles.
This one can't, because there's no normal code here to decompile. It's virtualized.

[aside, lighter] Side note — this thing fought me before I even got it *running*. The host has a modern
security feature on called shadow stacks, and when the packed code tried to return through it, the whole
process just… fast-failed. Instant crash. Turning that off was step zero. The protector doesn't play nice,
even with the operating system.

So — if I can't read the logic statically, I do what I did with the unpacker: I *run* it, and I watch what it
produces.

**[Screen: terminal — the dynamic step. Run the gate with no license; print the mask for each feature.]**

No license installed. Dumper?

**[Screen: 0x1000.]**

Trap. Injector? Trap. Editor? Trap. [flat] Everything's `0x1000`. Every feature, shut.

**[Screen: with a valid license present — the dumper mask.]**

And with a real license — dump comes back `0x450`. The actual process-dump rights. [beat]

There it is. I don't need to read the imaginary CPU. I've got the exact masks it hands out in both states —
licensed and not — and I've proven, live, that flipping the license is the *only* thing that moves them. And
if you go back to the callers —

**[Screen: IDA on the host with symbols — the dumper call site decompiled: `access = sip_access_mask(...)`
feeding straight into `PhOpenProcess(&handle, access, pid)`.]**

— it reads exactly like the picture. The mask comes out of the gate and goes straight into the kernel call.
Clean. The VMProtect side is understood.

---

## §4 — Breaking Themida  ~10:00–14:00

**[Screen: back to terminal; the plugin binary.]**

Now the plugin. The Themida one. And Themida has a trick that's genuinely mean.

**[ANIM: IAT — a normal import table: slot → real API in a system DLL.]**

Every program has an import table — a list of the system functions it calls, each one a slot pointing at the
real function. `LoadLibrary`, `WriteProcessMemory`, and so on. It's the first thing you read to understand
what a binary *does*.

**[ANIM: IAT — the slots now point into the protector's own stubs instead.]**

Themida rewrites that table. Every slot now points at *its own* code — a little wrapper buried inside the
protector that eventually, after some obfuscation, jumps to the real function. So if you just read the import
table, you learn nothing. Every call goes through the protector first.

[matter-of-fact] You can't fix that by hand — there are hundreds of them. So you automate it. For each slot,
you emulate the wrapper until it stops wrapping and finally jumps somewhere real — and *that* address tells
you which API it was hiding.

But first I need the unpacked code, and the clean on-disk file won't give it to me. So I take it from a
*running* copy.

**[Screen: the capture command — a full-memory dump of the live process. Watch the size climb.]**

That's the whole process — 216 megabytes of live memory, everything decrypted, exactly as it runs.

**[Screen: carve the plugin module out of the dump; then the unwrap running.]**

Carve the plugin out of that dump, and turn the unwrapper loose on its import table.

**[Screen: the unwrap log resolving slot after slot.]**

And now it just… walks them. Six hundred and fifty-one of them emulated straight through. Eleven more that
point directly. Which leaves —

**[Screen: 662 / 663. One unresolved.]**

[beat, deadpan] — one. Six hundred and sixty-two of six hundred and sixty-three.

[a little exasperated, affectionate] One stubborn thunk. And of course it's a special one — it's the function
that *terminates the process*. I can't emulate a wrapper whose whole job is to call "exit," or my emulator
exits with it. [beat] So I don't emulate it. I look it up — the clean build I kept knows that slot by name,
and I just borrow the answer.

**[Screen: 663 / 663.]**

Six hundred and sixty-three of six hundred and sixty-three. [quiet, satisfied] All of them.

**[Screen: rebuild the clean PE; run DIE on it.]**

Rebuild it into a clean file — imports restored, the protector's sections dropped — run the detector back over
it, and… no Themida. It's just a normal DLL again. [beat] The wrapping's gone.

---

## §5 — The KDF  ~14:00–17:00

**[Screen: terminal. The gate, the license file.]**

One piece left — the part I'd been avoiding. The crypto.

That license file isn't plaintext. The access masks — the `0x450`, the real rights — are *encrypted* inside
it. The gate derives a key, decrypts the entitlements, and only then does it have the numbers to hand out. If
I want to forge a license, I have to know exactly how that key is built.

And the key derivation is inside the VMProtected core. Virtualized. [flat] So reading it statically is off the
table — same wall as before.

But crypto has to touch the real world eventually. It calls the operating system's actual crypto library. So I
don't read the code — I *watch the calls*. I hook every crypto function the process touches and just let it run.

**[Screen: run the crypto tracer against the live process. The output is… empty.]**

[beat] And I get… nothing. [flat] No calls. Zero.

[the mood drops — this is the despair beat, play it] Which, after everything else, I read exactly one way:
VMProtect is hiding the crypto too. Virtualizing the calls, bypassing the normal library. [quietly] Of course
it is. Why would this be the easy part.

**[Screen: staring at the empty log. A pause on screen.]**

So I spent a while convinced I was beaten on this one.

[a turn, lighter] And then I actually read my own hook code. [beat] And the trace wasn't catching nothing
because the crypto was hidden. It was catching nothing because *my tool was wrong.* The scripting library had
changed one function in a new version — the exact call I used to find exports had been *removed* — so I was
installing hooks on… nothing. Silently. No error. [dry] An empty log that looked exactly like defeat.

**[Screen: fix the one line; re-run the tracer. The log explodes with calls.]**

One line. And —

**[ANIM: KDF — the call sequence assembling: hash → hash → hash, then the symmetric key, then decrypt.]**

— there's the whole thing. A hash-based key derivation — SHA-256, run in passes — building a key out of your
hardware ID, the publisher's signing key, and a checksum of the binary itself. [that's the "aha", say it like
one] *That's* why patching the binary broke the feature back at the start — change one byte and the checksum
changes, and the key comes out wrong, and the whole thing fails closed. It was all connected.

And then that derived key drives an AES decrypt — and *out* come the real access masks. [beat] The ones I'd
only ever seen as numbers are now something I can reproduce. The license is understood, end to end.

---

## §6 — The payoff  ~17:00–19:00

**[Screen: the signer tool. Issue a license for this machine's hardware ID.]**

So let's use it. I hold the signing side now — hardware ID, the entitlements, the masks — sign it, and write
the license file next to the executable.

**[Screen: drop `SystemInformer.sipm` next to the exe. Launch System Informer. Open Help → About.]**

**[Screen: the About box — status flips to licensed / Pro.]**

[quiet] Pro.

**[Screen: right-click a process → the Pro submenu. The three items are *live* now — not greyed.]**

And the menu. [beat] All three. Lit.

**[Screen: run the memory dumper on a process — a dump file lands on disk. Then the live editor — read an
address, change a value, write it back.]**

Dump — real file, real process. The editor — read memory, change it, write it back, and it *takes*.

[warm, earned] Same executable I started with. I never patched a single byte of it. I didn't crack the code —
I cracked the *license*, the way it was actually meant to be issued. The features were always there. I just
finally convinced the gate to open.

---

## §7 — Outro  ~19:00–20:00

**[Screen: a quick montage — the DIE output, the OEP snapshot, the 663/663, the KDF trace.]**

Let's be honest about what this was. Two commercial protectors. A license fused into kernel access rights so
there's no check to patch. Encrypted entitlements behind a key derivation tied to the hardware, the publisher,
and the binary itself. [beat] This is what real software protection looks like now. Not a jump you flip.

**[Screen: the toolchain repo — the reusable pieces.]**

And none of the tools I used here were one-offs. The unpacker, the import un-wrapper, the crypto tracer, the
little animation you saw explaining the mask — they're all general. Next target, I point them somewhere new
and most of the work's already done. [aside] That's the actual game: reverse something once, and walk away
with tools.

[direct, friendly] If you want to see the next one — whatever it is — you know what to do. [beat] I'll see you
in that one.

**[End card.]**

---

## Animation build list (from §-callouts)

| Beat | Used in | Status |
|------|---------|--------|
| `mask` — the branchless gate | §0, §1 | **built** (`reaforge/viz/branchless_mask.py`) |
| `protectors` — packing vs virtualization | §2 | to build |
| `unpack` — packed → OEP under emulation | §3 | to build |
| `IAT` — import slot → protector stub → real API | §4 | to build |
| `KDF` — hash passes → AES decrypt chain | §5 | to build |
