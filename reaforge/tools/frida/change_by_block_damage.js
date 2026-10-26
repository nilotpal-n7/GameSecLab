// Phase 3 warm-up (Veloren) — MODIFY: block all damage at Health::change_by.
//
// Same hook as the logger (veloren-voxygen.exe + 0xF4D9B3), but we change a
// register BEFORE the store runs. r15 holds the new current about to be written;
// if it's lower than the old current (= damage), we overwrite r15 with the old
// value, so the store writes "no change". This is argument/register modification
// — the second half of hooking, after observation.
//
// *** WARNING — read before running ***
// This choke point serves EVERY entity's health. Blocking all decreases here makes
// ENEMIES invincible too, so you may be unable to kill anything. That is the point:
// a naive hook at a shared function is indiscriminate. The real skill (Phase 3
// proper) is FILTERING to the player's entity — which needs a way to identify the
// player's Health pointer (e.g. the one matching the HUD / the address CE found).
// Treat this as a demonstration, not a usable cheat. Restart the game to clear it.

const MODULE = 'veloren-voxygen.exe';
const RVA_STORE = 0xF4D9B3;
const SCALE = 256.0;

// Optional: set this to a Health* (e.g. "0x3204EDA8000") to affect ONLY that entity.
// Leave null to affect everyone (the indiscriminate demo).
const ONLY_ENTITY = null;

const base = Process.getModuleByName(MODULE).base;
const target = base.add(RVA_STORE);
const onlyPtr = ONLY_ENTITY ? ptr(ONLY_ENTITY) : null;
console.log('[+] base = ' + base + '  hook @ ' + target);
console.log('[+] mode = ' + (onlyPtr ? ('ONLY ' + onlyPtr) : 'ALL entities (enemies become invincible too)'));

let blocked = 0;
Interceptor.attach(target, {
  onEnter(args) {
    const self = this.context.rcx;
    if (onlyPtr && !self.equals(onlyPtr)) return;

    const oldScaled = self.add(0x50).readU32();
    const newScaled = this.context.r15.toUInt32();

    if (newScaled < oldScaled) {                 // this write is damage
      this.context.r15 = ptr(oldScaled);         // write the OLD value instead -> no damage
      blocked++;
      if (blocked % 20 === 1) {
        console.log('[blocked ' + blocked + '] entity@' + self +
          ' kept ' + (oldScaled / SCALE).toFixed(1) + ' HP (ignored -' +
          ((oldScaled - newScaled) / SCALE).toFixed(1) + ')');
      }
    }
  }
});

console.log('[+] damage blocker installed. Restart the game to remove it.');
