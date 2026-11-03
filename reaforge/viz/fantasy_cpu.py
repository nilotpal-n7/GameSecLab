#!/usr/bin/env python3
r"""Beat: the fantasy CPU -- virtualization (§5), the showstopper.

The gate function turns out to be a three-instruction doorway: load a pointer, jump. The real logic was
translated into bytecode for an instruction set that exists in no real processor, run by an interpreter
shipped inside the program. Ask the decompiler for the C and it produces nothing -- which is the proof the
logic is virtualized, not a failure.

    manim -ql reaforge/viz/fantasy_cpu.py FantasyCpu
"""

from __future__ import annotations

from manim import DOWN, LEFT, RIGHT, UP, Arrow, Create, CurvedArrow, FadeIn, FadeOut, Indicate, SurroundingRectangle, Write

from reaforge.viz.kit import ACCENT, FALSE, GOLD, MUTED, ReScene, caption, code_lines, mono, stage_box

STUB = ("mov   ebx, ecx", "lea   rcx, [bytecode]", "jmp   dispatcher")
BYTECODE = ("VOP_2A  7F 03 D1", "VOP_11  C9 5E", "VOP_A4  80 12 6B", "VOP_0E  A2", "VOP_3C  90 4D 1F")


class FantasyCpu(ReScene):
    def construct(self) -> None:
        title = mono("A CPU that doesn't exist.", size=40, color=GOLD)
        self.play(Write(title), run_time=1.0)
        self.wait(0.7)
        self.play(FadeOut(title))

        # the gate function is a three-instruction doorway
        stub = code_lines(list(STUB), size=22, color=ACCENT).move_to(LEFT * 4.2 + UP * 1.7)
        sframe = SurroundingRectangle(stub, color=ACCENT, buff=0.22)
        stag = caption("the gate function", size=22).next_to(sframe, UP, buff=0.25)
        self.play(FadeIn(stub), Create(sframe), FadeIn(stag))
        door = caption("load a pointer, and jump. that's the whole function.", size=22).to_edge(DOWN, buff=0.6)
        self.play(FadeIn(door))
        self.wait(1.1)
        self.play(FadeOut(door))

        # ...which jumps into a made-up instruction set run by an interpreter
        disp = stage_box("VM dispatcher", color=GOLD, width=3.4, height=1.3).move_to(RIGHT * 2.6)
        loop = CurvedArrow(
            disp.get_right() + UP * 0.35, disp.get_right() + DOWN * 0.35, angle=-3.4, color=GOLD, tip_length=0.2
        )
        a_stub = Arrow(sframe.get_right(), disp.get_top(), buff=0.2, color=ACCENT, stroke_width=3)
        self.play(Create(a_stub), FadeIn(disp), Create(loop))

        bytecode = code_lines(list(BYTECODE), size=20, color=FALSE).move_to(LEFT * 4.2 + DOWN * 1.9)
        btag = caption("a made-up instruction set", size=20, color=FALSE).next_to(bytecode, UP, buff=0.25)
        a_bc = Arrow(bytecode.get_right(), disp.get_bottom(), buff=0.2, color=FALSE, stroke_width=3)
        self.play(FadeIn(bytecode), FadeIn(btag), Create(a_bc))
        for _ in range(3):
            self.play(Indicate(disp, color=GOLD, scale_factor=1.05), run_time=0.35)
        note = caption("run by an interpreter shipped inside the program", size=22, color=GOLD)
        note.to_edge(DOWN, buff=0.6)
        self.play(FadeIn(note))
        self.wait(1.1)

        # ask the decompiler -> nothing. that IS the proof.
        self.play(
            FadeOut(stub), FadeOut(sframe), FadeOut(stag), FadeOut(a_stub), FadeOut(a_bc),
            FadeOut(bytecode), FadeOut(btag), FadeOut(note), FadeOut(loop),
            disp.animate.move_to(UP * 2.3).scale(0.8),
        )
        dec = stage_box("decompiler", color=ACCENT, width=3.2, height=1.0).move_to(LEFT * 3.0)
        out = code_lines(["/* virtualized body:", "   no native code */"], size=24, color=MUTED)
        out.move_to(RIGHT * 2.2)
        a_dec = Arrow(dec.get_right(), out.get_left(), buff=0.3, color=MUTED, stroke_width=3)
        self.play(FadeIn(dec), Create(a_dec), FadeIn(out))
        punch = caption("that's not a failure -- that IS the proof it's virtualized", size=24, color=GOLD)
        punch.to_edge(DOWN, buff=0.7)
        self.play(Write(punch))
        self.wait(1.5)
