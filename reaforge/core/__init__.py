"""REAForge core — arch-agnostic VMProtect devirtualization engine.

engine.py  taint-symbolic core (x86-32/64)      loader.py  VMProtect env (EXE/DLL, 32/64)
peel.py    round peeling + anti-unify + proofs   __main__.py  authorization-gated title CLI

Category engines live in ``categories/`` and per-title configs in ``targets/`` — this package is the
shared mechanism both build on. Importing loader needs vmp-lazy-unpack on sys.path (see __main__.py),
so this __init__ intentionally imports nothing heavy.
"""
