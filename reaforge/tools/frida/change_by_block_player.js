// Phase 3 warm-up (Veloren) — PLAYER-ONLY damage block.
//
// The hook at veloren-voxygen.exe + 0xF4D9B3 fires for EVERY entity (ECS: one
// Health::change_by serves them all). To protect only the player we must first
// identify which Health* is the player's. We can't read that from the hook alone,
// so we identify it BY BEHAVIOUR:
//
//   CALIBRATE phase: for a few seconds you let an enemy hit you and DON'T attack.
//   The only entity taking damage is you, so it wins the damage tally and we lock it.
//   LOCKED phase: block damage only for that entity; everything else dies normally.
//
// Verified live: locked PLAYER=0x...718000 (max 100); player HP held while enemies died.
// Run with:  python run_hook.py change_by_block_player.js
// (Addresses change every launch — the auto-calibration re-finds the player each run.)

const MODULE = 'veloren-voxygen.exe';
const RVA_STORE = 0xF4D9B3;          // mov [rcx+0x50], r15d  -> self.current = new
const SCALE = 256.0;
const LOCK_MIN_HITS = 6;             // need this many damage events on the leader
const LOCK_MIN_MS = 6000;            // ...and at least this long, before locking

const base = Process.getModuleByName(MODULE).base;
const target = base.add(RVA_STORE);

let mode = 'calibrate';              // 'calibrate' -> 'locked'
let player = null;
const tally = {};                    // Health* string -> damage-event count
let blocked = 0;
const started = Date.now();

Interceptor.attach(target, {
  onEnter() {
    const self = this.context.rcx;
    const old  = self.add(0x50).readU32();
    const nw   = this.context.r15.toUInt32();
    const isDamage = nw < old;

    if (mode === 'calibrate') {
      if (isDamage) {
        const k = self.toString();
        tally[k] = (tally[k] || 0) + 1;
      }
      return;                        // observe only; don't block while calibrating
    }
    // locked: block damage for the player entity ONLY
    if (isDamage && self.equals(player)) {
      this.context.r15 = ptr(old);   // write old value -> no damage
      blocked++;
    }
  }
});

console.log('[cal] CALIBRATING: let an enemy hit you and DO NOT attack for ~8s...');

setInterval(() => {
  if (mode === 'calibrate') {
    let best = null, bestN = 0;
    for (const k in tally) if (tally[k] > bestN) { bestN = tally[k]; best = k; }
    if (best && bestN >= LOCK_MIN_HITS && (Date.now() - started) > LOCK_MIN_MS) {
      player = ptr(best);
      const max = player.add(0x58).readU32() / SCALE;
      mode = 'locked';
      console.log('[lock] PLAYER = ' + player + '  max=' + max + ' -> blocking ONLY you. Fight!');
    } else {
      console.log('[cal] candidates=' + Object.keys(tally).length + ' leaderHits=' + bestN);
    }
  } else {
    console.log('[locked] player=' + player + ' blocked=' + blocked);
  }
}, 1000);
