#!/usr/bin/env python3
"""
Small file operations inside Obsidian's iTunes file-sharing folder on an
attached iOS device, through pymobiledevice3's house_arrest (the AFC service
the Files app and Finder use). One process per call, but a directory listing
or a single file read costs a round trip, not a pull of the whole vault.

    ios-afc.py UDID ls DIR          every file under DIR, one path per line, relative to DIR
    ios-afc.py UDID cat FILE        the file's bytes on stdout (exit 2 when missing)
    ios-afc.py UDID write FILE      stdin to FILE, creating parent directories
    ios-afc.py UDID rm PATH         remove a file or a directory tree (missing is fine)
    ios-afc.py UDID exists PATH     exit 0 or 2

Paths are inside the app container, e.g. /Documents/obsync/notes/a.md.
Run with the interpreter of the pymobiledevice3 install
(`uv tool install pymobiledevice3` puts it under ~/.local/share/uv/tools/pymobiledevice3/bin/python).
"""
import asyncio
import posixpath
import sys

from pymobiledevice3.exceptions import AfcException
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.house_arrest import HouseArrestService

BUNDLE = "md.obsidian"


async def main() -> int:
    udid, cmd, path = sys.argv[1], sys.argv[2], sys.argv[3]
    lockdown = await create_using_usbmux(serial=udid)
    afc = await HouseArrestService.create(lockdown, BUNDLE, documents_only=True)
    try:
        if cmd == "ls":
            out = []
            async for root, _dirs, files in afc.walk(path):
                for f in files:
                    out.append(posixpath.relpath(posixpath.join(root, f), path))
            sys.stdout.write("\n".join(sorted(out)) + ("\n" if out else ""))
            return 0
        if cmd == "cat":
            try:
                data = await afc.get_file_contents(path)
            except AfcException:
                return 2
            sys.stdout.buffer.write(data)
            return 0
        if cmd == "write":
            parent = posixpath.dirname(path)
            if not await afc.exists(parent):
                await afc.makedirs(parent)
            await afc.set_file_contents(path, sys.stdin.buffer.read())
            return 0
        if cmd == "rm":
            if await afc.exists(path):
                await afc.rm(path, force=True)
            return 0
        if cmd == "exists":
            return 0 if await afc.exists(path) else 2
        sys.stderr.write(f"unknown command {cmd}\n")
        return 64
    finally:
        try:
            await afc.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
