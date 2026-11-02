#!/usr/bin/env python3
r"""Reusable primitives for reaforge RE-explainer video beats (Manim 0.19).

One visual language across every beat and target: a dark terminal palette, a single monospace face, and
a handful of mobject builders (bit strips, labelled value boxes, code lines, captions). Beats compose
these; they never hardcode colours or fonts. Keeping this in one place is what makes a cut look like one
channel instead of AI slop.

Nothing here imports a target -- beats pass in the numbers.
"""

from __future__ import annotations

from manim import BLACK, DOWN, LEFT, ORIGIN, RIGHT, UP, Rectangle, RoundedRectangle, Scene, Text, VGroup

# -- palette (GitHub-dark terminal; high contrast, colour-blind-safe true/false) -----------------
BG = "#0d1117"
FG = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#39c5cf"  # cyan -- highlight / the mask itself
TRUE = "#3fb950"  # green -- licensed / bit set / value survives
FALSE = "#f85149"  # red -- trap / denied / masked out
GOLD = "#d29922"  # emphasis on a single result

FONT = "Consolas"  # present on Windows; Pango falls back cleanly if not


def mono(text: str, size: float = 32, color: str = FG, weight: str = "NORMAL") -> Text:
    """A line of monospace text in the kit face/colour."""
    return Text(text, font=FONT, font_size=size, color=color, weight=weight)


def caption(text: str, size: float = 26, color: str = MUTED) -> Text:
    """Muted sub-line (narration echo / aside); pass color for an emphasised aside."""
    return mono(text, size=size, color=color)


def bits_of(value: int, nbits: int) -> list[int]:
    """MSB-first bit list of `value` in `nbits` (what a strip draws left-to-right)."""
    return [(value >> i) & 1 for i in range(nbits - 1, -1, -1)]


def bit_strip(
    value: int,
    nbits: int = 16,
    cell: float = 0.3,
    on: str = ACCENT,
    off: str = MUTED,
    nibble_gap: float = 0.12,
    show_bits: bool = False,
) -> VGroup:
    """A row of `nbits` little squares, MSB on the left, filled when the bit is set.

    Grouped in nibbles with a small gap so a hex value is readable at a glance. The returned VGroup
    carries `.value` and `.nbits` so a beat can Transform one strip into another cleanly.
    """
    cells = VGroup()
    bits = bits_of(value, nbits)
    for idx, b in enumerate(bits):
        sq = Rectangle(width=cell, height=cell, stroke_width=1.4)
        sq.set_stroke(color=on if b else off)
        sq.set_fill(color=on if b else BG, opacity=0.9 if b else 0.0)
        if idx:
            gap = cell + (nibble_gap if idx % 4 == 0 else cell * 0.18)
            sq.next_to(cells[-1], RIGHT, buff=0).shift(RIGHT * (gap - cell))
        cells.add(sq)
        if show_bits:
            lbl = mono(str(b), size=cell * 46, color=on if b else off).move_to(sq)
            cells.add(lbl)
    cells.value = value  # type: ignore[attr-defined]
    cells.nbits = nbits  # type: ignore[attr-defined]
    return cells


def value_box(hex_text: str, label: str = "", color: str = FG, width: float = 2.4) -> VGroup:
    """A labelled hex value in a rounded box -- a register / mask / access value."""
    box = Rectangle(width=width, height=0.8, stroke_width=2, stroke_color=color)
    box.set_fill(color=BLACK, opacity=0.25)
    val = mono(hex_text, size=30, color=color).move_to(box)
    group = VGroup(box, val)
    if label:
        tag = caption(label, size=22).next_to(box, UP, buff=0.14)
        group.add(tag)
    return group


def pill(text: str, color: str = FG, fill: bool = False, size: float = 24, pad: float = 0.34) -> VGroup:
    """A rounded, auto-sized labelled chip -- an input, an operand, a named stage in a pipeline."""
    label = mono(text, size=size, color=BLACK if fill else color)
    box = RoundedRectangle(corner_radius=0.16, width=label.width + pad * 2, height=label.height + pad)
    box.set_stroke(color=color, width=2)
    box.set_fill(color=color if fill else BG, opacity=0.95 if fill else 0.25)
    return VGroup(box, label)


def stage_box(text: str, color: str = ACCENT, width: float = 3.4, height: float = 1.0) -> VGroup:
    """A labelled processing stage (a function / transform) the pipeline flows through."""
    box = Rectangle(width=width, height=height, stroke_width=2.2, stroke_color=color)
    box.set_fill(color=color, opacity=0.08)
    return VGroup(box, mono(text, size=26, color=color).move_to(box))


def code_lines(lines: list[str], size: float = 22, color: str = MUTED) -> VGroup:
    """A left-aligned stack of monospace lines (a call log / disasm). Index it to highlight one: a
    beat recolours g[i] to ACCENT as each call fires."""
    g = VGroup(*[mono(ln, size=size, color=color) for ln in lines])
    g.arrange(DOWN, buff=0.2, aligned_edge=LEFT)
    return g


class ReScene(Scene):
    """Base scene: dark background + kit defaults. Beats subclass this (not Scene)."""

    def setup(self) -> None:
        super().setup()
        self.camera.background_color = BG


__all__ = [
    "ACCENT",
    "BG",
    "DOWN",
    "FALSE",
    "FG",
    "FONT",
    "GOLD",
    "LEFT",
    "MUTED",
    "ORIGIN",
    "RIGHT",
    "TRUE",
    "UP",
    "ReScene",
    "bit_strip",
    "bits_of",
    "caption",
    "code_lines",
    "mono",
    "pill",
    "stage_box",
    "value_box",
]
