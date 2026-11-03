#!/usr/bin/env python3
r"""Beat: the imports lie to you -- IAT detour + unwrap (§4).

A program's import table is the first thing you read to see what it does: each slot points at a real system
function. The protector rewrites every slot to point at its own obfuscation maze, which only eventually jumps
to the real function. You unwrap it by emulating each maze to its exit -- all 663 of them, one named from a
clean copy.

    manim -ql reaforge/viz/iat.py IatUnwrap
"""

from __future__ import annotations

from manim import DOWN, LEFT, RIGHT, UP, Arrow, Create, FadeIn, FadeOut, Indicate, VGroup, Write

from reaforge.viz.kit import ACCENT, FALSE, GOLD, MUTED, TRUE, ReScene, caption, mono, pill, stage_box

IMPORTS = ("LoadLibraryW", "WriteProcessMemory", "NtCreateThreadEx")


class IatUnwrap(ReScene):
    def construct(self) -> None:
        title = mono("Even the imports lie.", size=40, color=GOLD)
        self.play(Write(title), run_time=1.0)
        self.wait(0.6)
        self.play(FadeOut(title))

        slots = VGroup(*[pill(n, color=ACCENT) for n in IMPORTS])
        slots.arrange(DOWN, buff=0.7).move_to(LEFT * 4.6)
        stag = caption("import table", size=22).next_to(slots, UP, buff=0.35)
        real = stage_box("real functions", color=TRUE, width=3.0, height=4.0).move_to(RIGHT * 4.6)
        rtag = caption("ntdll / kernel32", size=20, color=TRUE).next_to(real, UP, buff=0.25)
        self.play(FadeIn(slots), FadeIn(stag), FadeIn(real), FadeIn(rtag))

        direct = VGroup(
            *[Arrow(s.get_right(), real.get_left(), buff=0.2, color=MUTED, stroke_width=3) for s in slots]
        )
        self.play(*[Create(a) for a in direct])
        n1 = caption("normally: each slot -> the real function", size=22).to_edge(DOWN, buff=0.6)
        self.play(FadeIn(n1))
        self.wait(1.0)

        # the protector slides its maze in between
        self.play(FadeOut(direct), FadeOut(n1))
        stub = stage_box("stub\nmaze", color=FALSE, width=2.4, height=2.2)
        in_arrows = VGroup(
            *[Arrow(s.get_right(), stub.get_left(), buff=0.2, color=FALSE, stroke_width=3) for s in slots]
        )
        out_arrow = Arrow(stub.get_right(), real.get_left(), buff=0.2, color=FALSE, stroke_width=3)
        self.play(FadeIn(stub), *[Create(a) for a in in_arrows], Create(out_arrow))
        n2 = caption("here: every slot detours through the protector's own code", size=22, color=FALSE)
        n2.to_edge(DOWN, buff=0.6)
        self.play(FadeIn(n2))
        self.play(Indicate(stub, color=FALSE))
        self.wait(1.0)

        # unwrap: follow each maze to its exit
        self.play(FadeOut(n2))
        resolved = Arrow(stub.get_right(), real.get_left(), buff=0.2, color=TRUE, stroke_width=4)
        self.play(FadeOut(out_arrow), Create(resolved))
        for s in slots:
            self.play(Indicate(s, color=TRUE), run_time=0.3)
        counter = mono("663 / 663  unwrapped", size=30, color=GOLD).move_to(UP * 2.6)
        self.play(Write(counter))
        n3 = caption("emulate each maze to its exit -- every import named", size=22, color=GOLD)
        n3.to_edge(DOWN, buff=0.6)
        self.play(FadeIn(n3))
        self.wait(1.4)
