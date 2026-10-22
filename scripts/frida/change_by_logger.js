// Phase 3 warm-up (Veloren) — LOG every Health::change_by write.
//
// We hook the exact store instruction verified in Phase 2:
//     veloren-voxygen.exe + 0xF4D9B3 :  mov [rcx+0x50], r15d
// At that instruction (confirmed by disassembly):
//     rcx = &mut Health   (the struct whose current HP is being written)
//     r15 (low 32 bits) = the NEW current, already clamped to maximum, scaled x256
//     [rcx+0x50] still holds the OLD current until the store runs
//     [rcx+0x58] = maximum (scaled x256)
//
// This fires for EVERY entity (ECS: one function serves all Health components),
// so you will see NPC hits too. That "it fires for everyone" is the core Phase 3
// lesson: a hook at a shared choke point needs a filter to isolate the player.

const MODULE = 'veloren-voxygen.exe';
const RVA_STORE = 0xF4D9B3;        // mov [rcx+0x50], r15d
const SCALE = 256.0;

const base = Process.getModuleByName(MODULE).base;
const target = base.add(RVA_STORE);
console.log('[+] ' + MODULE + ' base = ' + base);
console.log('[+] hooking change_by store @ ' + target + '  (base + 0x' + RVA_STORE.toString(16) + ')');

let n = 0;
Interceptor.attach(target, {
  onEnter(args) {
    const self = this.context.rcx;                 // Health*
    const oldScaled = self.add(0x50).readU32();    // current before the store
    const maxScaled = self.add(0x58).readU32();    // maximum
    const newScaled = this.context.r15.toUInt32(); // value about to be written (r15d)

    const oldHp = oldScaled / SCALE;
    const newHp = newScaled / SCALE;
    const delta = newHp - oldHp;
    if (Math.abs(delta) < 0.001) return;           // skip no-op writes

    n++;
    const tag = delta < 0 ? 'DMG ' : 'HEAL';
    console.log(
      '#' + n + ' ' + tag +
      ' entity@' + self +
      '  ' + oldHp.toFixed(1) + ' -> ' + newHp.toFixed(1) +
      '  (' + (delta < 0 ? '' : '+') + delta.toFixed(1) + ')' +
      '  max=' + (maxScaled / SCALE).toFixed(0)
    );
  }
});

console.log('[+] installed. Take a hit or heal in-game; Ctrl+C in the console to stop.');
