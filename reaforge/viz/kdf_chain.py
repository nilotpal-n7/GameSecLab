#!/usr/bin/env python3
r"""Beat: the license KDF -- HKDF-SHA256 -> AES-256-GCM (shot #5 of the walkthrough).

What `crypto_trace` caught the gate doing, drawn as a pipeline. Four inputs -- the machine's HWID, the
publisher's signing key, a CRC of the binary itself, and the product slug -- are run through HKDF-SHA256
(a chain of BCrypt hash passes, CNG) into a 256-bit key. That key drives an AES-256-GCM decrypt of the
license blob, and out come the real NtOpenProcess access masks (dump = 0x450, ...). The sting: one of those
inputs is a checksum of the binary, so patching a single byte makes the key wrong, GCM auth fails, and the
gate falls back to the trap mask -- which is exactly why NOPing the check at the start did nothing.

General `KdfChainScene` draws it for any inputs/calls/masks; `SiKdfChain` fills the numbers from
targets.system_informer.config.

    manim -ql reaforge/viz/kdf_chain.py SiKdfChain
"""

from __future__ import annotations

from manim import DOWN, LEFT, RIGHT, UP, Arrow, Create, FadeIn, FadeOut, Indicate, ReplacementTransform, VGroup, Write

from reaforge.viz.kit import ACCENT, FALSE, GOLD, MUTED, TRUE, ReScene, caption, code_lines, mono, pill, stage_box, value_box


def _hex32(v: int) -> str:
    return f"0x{v & 0xFFFFFFFF:08X}"


class KdfChainScene(ReScene):
    """Parameterised pipeline beat. Subclass and set the attributes; targets supply the numbers."""

    INGREDIENTS = ("HWID", "issuer pubkey", "binary CRC", "product slug")
    CRC_INDEX = 2  # which ingredient is the binary checksum (spotlit for the callback)
    HKDF_CALLS = ("BCryptOpenAlgorithmProvider", "BCryptCreateHash", "BCryptHashData", "BCryptFinishHash")
    AES_CALLS = ("GenerateSymmetricKey", "SetProperty  (GCM)", "Decrypt")
    MASKS = {"dump": 0x450, "inject": 0x2A, "edit": 0x38}
    TRAP = 0x1000

    def construct(self) -> None:
        self._title()
        key = self._hkdf()
        masks = self._aes(key)
        self._fail(masks)
        self.wait(1.2)

    def _title(self) -> None:
        line = mono("The key is derived, never stored.", size=42, color=GOLD)
        sub = caption("Windows CNG / BCrypt -- hooked outside the VM", size=24).next_to(line, DOWN, buff=0.3)
        self.play(Write(line), run_time=1.0)
        self.play(FadeIn(sub, shift=UP * 0.2))
        self.wait(0.9)
        self.play(FadeOut(line), FadeOut(sub))

    def _hkdf(self) -> VGroup:
        ings = VGroup(*[pill(t, color=ACCENT) for t in self.INGREDIENTS])
        ings.arrange(RIGHT, buff=0.4).move_to(UP * 2.5)
        self.play(FadeIn(ings, shift=DOWN * 0.2, lag_ratio=0.2))
        self.wait(0.3)

        hk = stage_box("HKDF - SHA-256", color=ACCENT, width=4.2).move_to(UP * 0.35)
        arrow_in = Arrow(ings.get_bottom(), hk.get_top(), buff=0.15, color=MUTED, stroke_width=3)
        self.play(Create(arrow_in), FadeIn(hk))

        log = code_lines(list(self.HKDF_CALLS), size=19).next_to(hk, RIGHT, buff=0.6)
        self.play(FadeIn(log))
        for ln in log:
            self.play(ln.animate.set_color(ACCENT), run_time=0.3)
        note = caption("extract + expand passes", size=22).move_to(LEFT * 4.3 + UP * 1.3)
        self.play(FadeIn(note))

        key = pill("256-bit key", color=GOLD).move_to(DOWN * 2.3)
        arrow_key = Arrow(hk.get_bottom(), key.get_top(), buff=0.15, color=GOLD, stroke_width=3)
        self.play(Create(arrow_key), FadeIn(key, shift=DOWN * 0.2))
        self.play(Indicate(key, color=GOLD))
        self.wait(0.4)

        # plant the callback: one input is a checksum of the binary itself
        crc = ings[self.CRC_INDEX]
        plant = caption("one input is a checksum of the binary itself", size=22, color=GOLD)
        plant.next_to(ings, DOWN, buff=0.2)
        self.play(Indicate(crc, color=GOLD), FadeIn(plant))
        self.wait(0.9)

        self.play(FadeOut(ings), FadeOut(log), FadeOut(hk), FadeOut(note), FadeOut(arrow_in), FadeOut(arrow_key), FadeOut(plant))
        self.play(key.animate.move_to(LEFT * 3.4 + UP * 2.4))
        return key

    def _aes(self, key: VGroup) -> VGroup:
        blob = pill("license blob  (ciphertext)", color=FALSE).move_to(RIGHT * 3.4 + UP * 2.4)
        self.play(FadeIn(blob, shift=DOWN * 0.2))

        aes = stage_box("AES-256-GCM  decrypt", color=ACCENT, width=5.0).move_to(UP * 0.35)
        a_key = Arrow(key.get_bottom(), aes.get_top() + LEFT * 1.2, buff=0.15, color=GOLD, stroke_width=3)
        a_blob = Arrow(blob.get_bottom(), aes.get_top() + RIGHT * 1.2, buff=0.15, color=FALSE, stroke_width=3)
        self.play(Create(a_key), Create(a_blob), FadeIn(aes))

        log = code_lines(list(self.AES_CALLS), size=19).next_to(aes, RIGHT, buff=0.55)
        self.play(FadeIn(log))
        for ln in log:
            self.play(ln.animate.set_color(ACCENT), run_time=0.3)

        masks = VGroup(*[value_box(_hex32(v), label=name, color=TRUE, width=2.5) for name, v in self.MASKS.items()]).arrange(RIGHT, buff=0.5).move_to(DOWN * 2.4)
        arrow_out = Arrow(aes.get_bottom(), masks.get_top(), buff=0.15, color=TRUE, stroke_width=3)
        self.play(Create(arrow_out), FadeIn(masks, shift=DOWN * 0.2))
        done = caption("the entitlements decrypt  ->  the real access masks", size=24).next_to(masks, DOWN, buff=0.3)
        self.play(FadeIn(done))
        self.play(Indicate(masks, color=TRUE))
        self.wait(1.1)

        self.play(FadeOut(key), FadeOut(blob), FadeOut(aes), FadeOut(log), FadeOut(a_key), FadeOut(a_blob), FadeOut(arrow_out), FadeOut(done))
        self.play(masks.animate.move_to(DOWN * 0.3))
        return masks

    def _fail(self, masks: VGroup) -> None:
        note = caption("patch one byte  ->  CRC changes  ->  key is wrong", size=26, color=FALSE).move_to(UP * 2.3)
        self.play(Write(note))
        self.wait(0.4)

        trap = VGroup(*[value_box(_hex32(self.TRAP), label=name, color=FALSE, width=2.5) for name in self.MASKS]).arrange(RIGHT, buff=0.5).move_to(masks)
        self.play(ReplacementTransform(masks, trap))
        self.play(Indicate(trap, color=FALSE))
        punch = caption("GCM auth fails  ->  the gate returns the trap mask", size=22, color=FALSE).next_to(trap, DOWN, buff=0.5)
        self.play(Write(punch))
        self.wait(1.4)


class SiKdfChain(KdfChainScene):
    """System Informer license KDF, masks from the target config."""

    def __init__(self, *a, **k):
        from targets.system_informer.config import MASK, MASK_TRAP

        type(self).MASKS = dict(MASK)
        type(self).TRAP = MASK_TRAP
        super().__init__(*a, **k)
