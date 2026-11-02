r"""reaforge.viz -- a small Manim scene-kit for RE-explainer video beats.

General, reusable building blocks (palette, mono text, bit strips, value/register boxes, a dark Scene
base) live in `kit`; one file per *beat* layers a concrete animation on top. Targets supply only the
numbers (e.g. targets.system_informer.config.MASK), never presentation -- same split as the rest of
reaforge (general glue here, target specifics + evidence under targets/).

Render a beat (Manim 0.19):
    manim -ql reaforge/viz/branchless_mask.py SiProDumpMask     # 480p preview
    manim -qh reaforge/viz/branchless_mask.py SiProDumpMask     # 1080p final
output lands in media/videos/<file>/<quality>/<Scene>.mp4
"""
