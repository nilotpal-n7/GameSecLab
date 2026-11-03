#!/usr/bin/env python3
r"""Beat: the weapons wall -- what defends three menu options (hook §1, outro §9).

The thesis shot. On the left, the thing being protected: three greyed-out Pro menu items, small and
unremarkable. On the right, the arsenal guarding them, slamming in one weapon at a time until it towers --
a bank-vault door on a garden shed. Not a technical beat; a gut-punch of scale.

    manim -ql reaforge/viz/arsenal.py ArsenalWall
"""

from __future__ import annotations

from manim import DOWN, LEFT, RIGHT, UP, FadeIn, Indicate, Rectangle, RoundedRectangle, VGroup, Write

from reaforge.viz.kit import BG, FALSE, GOLD, MUTED, ReScene, caption, mono

WEAPONS = (
    "Hardware binding",
    "OS fingerprinting",
    "Encryption",
    "Obfuscation",
    "Debugger checks",
    "Integrity checks",
    "Anti-tamper",
    "Timing checks",
    "A fantasy CPU",
    "Self-rewriting code",
)


def _tile(name: str, color: str, width: float = 4.0, height: float = 0.5) -> VGroup:
    box = Rectangle(width=width, height=height, stroke_width=2, stroke_color=color)
    box.set_fill(color=color, opacity=0.1)
    return VGroup(box, mono(name, size=19, color=color).move_to(box))


class ArsenalWall(ReScene):
    PROTECTS = ("Dump process memory", "Inject a DLL", "Edit live memory")

    def construct(self) -> None:
        # left: the modest thing being protected
        title_l = caption("what it protects", size=22).move_to(LEFT * 3.7 + UP * 2.7)
        rows = VGroup(*[mono(t, size=19, color=MUTED) for t in self.PROTECTS]).arrange(DOWN, buff=0.32, aligned_edge=LEFT)
        panel = self._panel(rows).next_to(title_l, DOWN, buff=0.4)
        self.play(FadeIn(title_l), FadeIn(panel))
        self.wait(0.5)

        vs = mono("vs", size=34, color=GOLD).move_to(LEFT * 0.3 + UP * 0.2)
        self.play(Write(vs))

        # right: the arsenal slamming in, one weapon at a time
        title_r = caption("what defends it", size=22, color=FALSE).move_to(RIGHT * 3.3 + UP * 3.1)
        self.play(FadeIn(title_r))
        tiles = VGroup()
        for name in WEAPONS:
            color = GOLD if name in ("A fantasy CPU", "Self-rewriting code") else FALSE
            tiles.add(_tile(name, color))
        tiles.arrange(DOWN, buff=0.12).next_to(title_r, DOWN, buff=0.28)
        for tile in tiles:
            self.play(FadeIn(tile, shift=LEFT * 0.3), run_time=0.22)
        self.play(Indicate(tiles, color=FALSE, scale_factor=1.03))
        self.wait(0.5)

        punch = caption("a bank-vault door on a garden shed", size=26, color=GOLD).to_edge(DOWN, buff=0.45)
        self.play(Write(punch))
        self.wait(1.5)

    def _panel(self, rows: VGroup) -> VGroup:
        box = RoundedRectangle(corner_radius=0.14, width=rows.width + 1.0, height=rows.height + 0.7, stroke_width=2)
        box.set_stroke(color=MUTED).set_fill(color=BG, opacity=0.4)
        rows.move_to(box).shift(RIGHT * 0.15)
        marks = VGroup(*[mono("x", size=18, color=FALSE).next_to(r, LEFT, buff=0.25) for r in rows])
        return VGroup(box, rows, marks)
