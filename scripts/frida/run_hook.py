#!/usr/bin/env python3
"""Attach Frida to Veloren and load a hook script. PATH-independent driver.

Usage (from any shell):
    python run_hook.py change_by_logger.js
    python run_hook.py change_by_block_damage.js

The game must already be running (singleplayer). Press Enter to detach.
"""
import sys, os, frida

TARGET = "veloren-voxygen.exe"

def main():
    if len(sys.argv) < 2:
        print("usage: python run_hook.py <script.js>")
        return 1
    script_path = sys.argv[1]
    if not os.path.isabs(script_path):
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_path)
    with open(script_path, "r", encoding="utf-8") as f:
        source = f.read()

    print(f"[*] attaching to {TARGET} ...")
    session = frida.attach(TARGET)            # raises if not running
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    print("[*] loaded. Play the game; press Enter here to detach.")
    try:
        input()
    except KeyboardInterrupt:
        pass
    session.detach()
    print("[*] detached.")
    return 0

def on_message(message, data):
    if message["type"] == "send":
        print(message["payload"])
    elif message["type"] == "error":
        print("[script error] " + message.get("stack", message.get("description", "?")))

if __name__ == "__main__":
    sys.exit(main())
