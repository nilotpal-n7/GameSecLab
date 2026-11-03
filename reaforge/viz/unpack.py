#!/usr/bin/env python3
r"""Beat: you can't even read it -- encrypted bytes -> decrypted snapshot (§4).

The file on disk is noise: the real code is encrypted and only unwraps itself in memory. So we run it inside
an emulator, let it decrypt itself, and freeze the memory the instant it reaches the real entry point -- a
corpse we can read without the live program ever feeling us.

    manim -ql reaforge/viz/unpack.py UnpackToSnapshot
"""

from __future__ import annotations

from manim import DOWN, LEFT, RIGHT, UP, Arrow, Create, FadeIn, FadeOut, Indicate, ReplacementTransform, SurroundingRectangle, Write

from reaforge.viz.kit import ACCENT, FALSE, GOLD, MUTED, TRUE, ReScene, caption, code_lines, mono, stage_box

NOISE = (
    "4F A2 1B C9 7E 03 D1 8A",
    "E6 11 9C 55 B0 2F 6D F4",
    "0A 77 C3 12 AE 59 80 BB",
    "D9 34 6F 21 93 EC 48 1D",
    "7C 5A B2 0E F1 86 3B A7",
    "22 C8 90 4D 1F E3 65 9B",
)
CODE = (
    "push   rbp",
    "mov    rbp, rsp",
    "sub    rsp, 0x40",
    "lea    rcx, [rip+key]",
    "call   sip_gate_init",
    "mov    [rbp-8], rax",
)


class UnpackToSnapshot(ReScene):
    def construct(self) -> None:
        title = mono("The file on disk is noise.", size=40, color=GOLD)
        self.play(Write(title), run_time=1.0)
        self.wait(0.7)
        self.play(FadeOut(title))

        noise = code_lines(list(NOISE), size=20, color=FALSE).move_to(LEFT * 4.3)
        ntag = caption("on disk: encrypted", size=22, color=FALSE).next_to(noise, UP, buff=0.3)
        self.play(FadeIn(noise), FadeIn(ntag))
        self.wait(0.5)

        emu = stage_box("emulator", color=ACCENT, width=3.0, height=1.2)
        arrow_in = Arrow(noise.get_right(), emu.get_left(), buff=0.2, color=MUTED, stroke_width=3)
        self.play(Create(arrow_in), FadeIn(emu))
        step = caption("run it in a sandbox; let it unpack itself", size=22).next_to(emu, DOWN, buff=0.5)
        self.play(FadeIn(step))
        for _ in range(3):
            self.play(Indicate(emu, color=ACCENT, scale_factor=1.06), run_time=0.4)

        code = code_lines(list(CODE), size=20, color=TRUE).move_to(RIGHT * 4.3)
        arrow_out = Arrow(emu.get_right(), code.get_left(), buff=0.2, color=TRUE, stroke_width=3)
        self.play(FadeOut(step), Create(arrow_out), ReplacementTransform(noise.copy(), code))
        oep = caption("OEP reached", size=22, color=TRUE).next_to(code, UP, buff=0.3)
        self.play(FadeIn(oep))
        self.wait(0.4)

        frame = SurroundingRectangle(code, color=GOLD, buff=0.25)
        snap = caption("snapshot: the real code, frozen", size=24, color=GOLD).to_edge(DOWN, buff=0.6)
        self.play(Create(frame), Write(snap))
        self.play(Indicate(frame, color=GOLD))
        self.wait(1.3)
