#!/usr/bin/env python3
r"""Beat: the branchless license gate (shot #2 of the System Informer walkthrough).

Shows the one idea that makes this gate un-patchable: the license state never reaches an `if`. The three
cached facts (entitled, crc_ok, nodbg) are AND-ed to a single bit g, g is NEGATED to a full-width mask m
(0 -> 0x00000000, 1 -> 0xFFFFFFFF), and the NtOpenProcess ACCESS_MASK is then *selected* with no branch:

    access = (base & m) | (trap & ~m)

Licensed -> m is all-ones -> access = base (the real right, e.g. dump = 0x450). Flip one input (a debugger
attaches, nodbg -> 0) -> m is all-zeros -> access = trap (0x1000): the handle still opens, the privileged
op is denied, and there is no compare instruction to NOP.

General `BranchlessMaskScene` draws it for any (base, trap, inputs); `SiProDumpMask` fills the numbers from
targets.system_informer.config so the beat and the real gate can never drift apart.

    manim -ql reaforge/viz/branchless_mask.py SiProDumpMask
"""

from __future__ import annotations

from manim import DOWN, LEFT, RIGHT, UP, Arrow, Create, FadeIn, FadeOut, Indicate, ReplacementTransform, VGroup, Write

from reaforge.viz.kit import ACCENT, FALSE, GOLD, MUTED, TRUE, ReScene, bit_strip, caption, mono, value_box

NBITS = 16  # low 16 bits hold every set bit of the SI masks; label shows the full 32-bit hex


def _hex32(v: int) -> str:
    return f"0x{v & 0xFFFFFFFF:08X}"


class BranchlessMaskScene(ReScene):
    """Parameterised beat. Subclass and set the five attributes; targets supply the numbers."""

    BASE = 0x450
    TRAP = 0x1000
    FEATURE = "SIP_FEAT_DUMP"
    FEATURE_NAME = "Process Memory Dumper"
    INPUTS = ("entitled", "crc_ok", "nodbg")

    def construct(self) -> None:
        self._title()
        self._formula()
        m_strip = self._mask_from_inputs()
        result = self._select(m_strip)
        self._flip(m_strip, result)
        self.wait(1.2)

    # -- phases ----------------------------------------------------------------------------------
    def _title(self) -> None:
        line = mono("The gate is not an  if .", size=46, color=GOLD)
        sub = caption("license state never reaches a compare", size=26).next_to(line, DOWN, buff=0.3)
        self.play(Write(line), run_time=1.1)
        self.play(FadeIn(sub, shift=UP * 0.2))
        self.wait(1.0)
        self.play(FadeOut(line), FadeOut(sub))

    def _formula(self) -> None:
        self.formula = mono(f"access = (base & m) | ({_hex32(self.TRAP)} & ~m)", size=30, color=ACCENT)
        self.formula.to_edge(UP, buff=0.5)
        self.mdef = caption("m = -(entitled & crc_ok & nodbg)", size=24).next_to(self.formula, DOWN, buff=0.18)
        self.play(Write(self.formula), run_time=1.0)
        self.play(FadeIn(self.mdef))
        self.wait(0.6)

    def _mask_from_inputs(self) -> VGroup:
        # three entitlement bits, all true (licensed) -- top band
        bits = VGroup()
        for name in self.INPUTS:
            cell = value_box("1", label=name, color=TRUE, width=1.2)
            bits.add(cell)
        bits.arrange(RIGHT, buff=0.5).move_to(UP * 1.35)
        self.play(FadeIn(bits, shift=UP * 0.2, lag_ratio=0.2))
        self.wait(0.4)

        # AND -> g
        g = value_box("1", label="g = all true", color=TRUE, width=1.6).move_to(UP * 0.05)
        arrow_g = Arrow(bits.get_bottom(), g.get_top(), buff=0.15, color=MUTED, stroke_width=3)
        self.play(Create(arrow_g), FadeIn(g, shift=DOWN * 0.2))
        self.play(Indicate(g, color=TRUE))
        self.wait(0.4)

        # negate g -> full-width mask m
        m_strip = bit_strip(0xFFFF, NBITS, on=ACCENT, off=MUTED)
        m_label = mono(_hex32(0xFFFFFFFF), size=26, color=ACCENT)
        m_row = VGroup(m_strip, m_label).arrange(RIGHT, buff=0.45)
        self._m_label = m_label
        m_tag = caption("m = -g", size=24).next_to(m_row, LEFT, buff=0.4)
        m_group = VGroup(m_tag, m_row).move_to(DOWN * 1.6)
        arrow_m = Arrow(g.get_bottom(), m_row.get_top(), buff=0.15, color=ACCENT, stroke_width=3)
        self.play(Create(arrow_m), FadeIn(m_group, shift=DOWN * 0.2))
        self.play(Indicate(m_strip, color=ACCENT))
        note = caption("one bit  ->  a 32-bit mask (all ones)", size=22).next_to(m_group, DOWN, buff=0.3)
        self.play(FadeIn(note))
        self.wait(1.0)

        self.play(FadeOut(bits), FadeOut(arrow_g), FadeOut(g), FadeOut(arrow_m), FadeOut(note))
        # lift the mask to its persistent band just under the formula
        self.play(m_group.animate.move_to(UP * 0.95))
        self._m_group = m_group
        return m_strip

    def _select(self, m_strip: VGroup) -> VGroup:
        base_strip = bit_strip(self.BASE, NBITS, on=TRUE, off=MUTED)
        base_lbl = mono(f"base {_hex32(self.BASE)}", size=24, color=TRUE)
        base_row = VGroup(base_strip, base_lbl).arrange(RIGHT, buff=0.45)
        trap_strip = bit_strip(self.TRAP, NBITS, on=FALSE, off=MUTED)
        trap_lbl = mono(f"trap {_hex32(self.TRAP)}", size=24, color=FALSE)
        trap_row = VGroup(trap_strip, trap_lbl).arrange(RIGHT, buff=0.45)
        rows = VGroup(base_row, trap_row).arrange(DOWN, buff=0.5, aligned_edge=LEFT).move_to(DOWN * 0.75)
        self.play(FadeIn(base_row, shift=RIGHT * 0.2), FadeIn(trap_row, shift=RIGHT * 0.2))
        self.wait(0.5)

        # m is all-ones: base & m survives, trap & ~m vanishes
        self.play(Indicate(m_strip, color=ACCENT), Indicate(base_strip, color=TRUE))
        self.play(trap_row.animate.set_opacity(0.25))
        access = self.BASE  # (base & 0xffff..) | (trap & 0)
        res_strip = bit_strip(access, NBITS, on=GOLD, off=MUTED)
        res_lbl = value_box(_hex32(access), label=f"access  {self.FEATURE}", color=GOLD, width=2.6)
        res_row = VGroup(res_strip, res_lbl).arrange(RIGHT, buff=0.5).move_to(DOWN * 2.6)
        arrow = Arrow(rows.get_bottom(), res_row.get_top(), buff=0.15, color=GOLD, stroke_width=3)
        self.play(Create(arrow), FadeIn(res_row, shift=DOWN * 0.2))
        self.play(Indicate(res_row, color=GOLD))
        good = caption(f"licensed  ->  {self.FEATURE_NAME} granted", size=24).next_to(res_row, DOWN, buff=0.3)
        self.play(FadeIn(good))
        self.wait(1.2)

        self._rows = rows
        self._trap_row = trap_row
        self._base_strip = base_strip
        self._arrow = arrow
        self._good = good
        self._access_strip = res_strip
        return res_row

    def _flip(self, m_strip: VGroup, result: VGroup) -> None:
        flip = caption("a debugger attaches   ->   nodbg = 0", size=26, color=FALSE).move_to(UP * 2.35)
        self.play(FadeOut(self._good), Write(flip))
        self.wait(0.3)

        # g -> 0  =>  m -> all zeros
        zero_m = bit_strip(0x0000, NBITS, on=ACCENT, off=MUTED).move_to(m_strip)
        zero_lbl = mono(_hex32(0x00000000), size=26, color=MUTED).move_to(self._m_label)
        self.play(ReplacementTransform(m_strip, zero_m), ReplacementTransform(self._m_label, zero_lbl))
        self.play(Indicate(zero_m, color=FALSE))

        # now (base & 0) | (trap & ~0) = trap : the selection flips
        self.play(self._trap_row.animate.set_opacity(1.0), self._rows[0].animate.set_opacity(0.25))
        trap_access = self.TRAP
        new_res = bit_strip(trap_access, NBITS, on=FALSE, off=MUTED)
        new_lbl = value_box(_hex32(trap_access), label="access  trap", color=FALSE, width=2.6)
        new_row = VGroup(new_res, new_lbl).arrange(RIGHT, buff=0.5).move_to(result)
        self.play(ReplacementTransform(result, new_row))
        self.play(Indicate(new_row, color=FALSE))
        bad = caption("handle opens, Pro op denied  -  no compare to NOP", size=24, color=FALSE)
        bad.next_to(new_row, DOWN, buff=0.3)
        self.play(FadeIn(bad))
        self.wait(1.4)


class SiProDumpMask(BranchlessMaskScene):
    """System Informer Pro -- Process Memory Dumper gate, numbers from the target config."""

    def __init__(self, *a, **k):
        from targets.system_informer.config import MASK, MASK_TRAP

        type(self).BASE = MASK["dump"]
        type(self).TRAP = MASK_TRAP
        super().__init__(*a, **k)
