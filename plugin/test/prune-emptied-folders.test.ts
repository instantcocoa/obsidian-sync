/**
 * Found in the field (2026-11-25): folders moved into another folder (or
 * deleted) on a Mac stayed behind on the phone as empty folders. Only files
 * are synced, so the move arrived as deletions under the old folder and puts
 * under the new one, and nothing removed the folder the deletions emptied.
 * The file counts matched; the file explorers did not.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { TestServer, Device } from "./harness";
import { createVault, createInviteLink, joinWithLink } from "../src/core/admin";
import { utf8 } from "../src/core/encoding";

let srv: TestServer;
beforeAll(async () => {
  srv = await TestServer.start();
});
afterAll(async () => {
  await srv.stop();
});

async function pair(): Promise<[Device, Device]> {
  const sa = await createVault(await srv.createLink(), "mac");
  const sb = await joinWithLink(await createInviteLink(sa), "phone");
  return [await new Device("mac", sa).start(), await new Device("phone", sb).start()];
}

describe("a folder emptied by another device's deletions", () => {
  it("is removed after the pull, with its emptied subfolders; folders that still hold something stay", async () => {
    const [a, b] = await pair();
    try {
      await a.rawWrite("Cocoa/plan.md", utf8("plan\n"));
      await a.rawWrite("Cocoa/deep/er/todo.md", utf8("todo\n"));
      await a.rawWrite("People/one.md", utf8("one\n"));
      await a.rawWrite("People/two.md", utf8("two\n"));
      await a.rawWrite("Keep/gone.md", utf8("gone\n"));
      await a.sync();
      await b.sync();
      writeFileSync(join(b.dir, "Cocoa/.DS_Store"), "junk");
      writeFileSync(join(b.dir, "Keep/written-here.md"), "a note the phone has not pushed yet");

      mkdirSync(join(a.dir, "Projects"));
      renameSync(join(a.dir, "Cocoa"), join(a.dir, "Projects/Cocoa"));
      rmSync(join(a.dir, "People/one.md"));
      rmSync(join(a.dir, "Keep/gone.md"));
      await a.sync();
      await b.sync();

      expect(await b.read("Projects/Cocoa/deep/er/todo.md")).toBe("todo\n");
      expect(existsSync(join(b.dir, "Cocoa"))).toBe(false);
      expect(existsSync(join(b.dir, "People/two.md"))).toBe(true);
      expect(existsSync(join(b.dir, "Keep"))).toBe(true);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });

  it("left behind by an earlier version is removed on the next start; a folder this device emptied itself is not", async () => {
    const [a, b] = await pair();
    try {
      await a.rawWrite("Old/x.md", utf8("x\n"));
      await a.rawWrite("Mine/y.md", utf8("y\n"));
      await a.sync();
      await b.sync();
      rmSync(join(a.dir, "Old/x.md"));
      await a.sync();
      await b.sync();
      // What 1.0.5 left on the phone: the tombstone in state, the folder on disk.
      mkdirSync(join(b.dir, "Old/sub"), { recursive: true });
      rmSync(join(b.dir, "Mine/y.md"));
      await b.sync();
      await b.restart();
      await b.sync();
      expect(existsSync(join(b.dir, "Old"))).toBe(false);
      expect(existsSync(join(b.dir, "Mine"))).toBe(true);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });

  it("is removed by a reset to the server's copy, even when it was already empty before the reset", async () => {
    const [a, b] = await pair();
    try {
      await a.rawWrite("Cocoa/plan.md", utf8("plan\n"));
      await a.sync();
      await b.sync();
      mkdirSync(join(a.dir, "Projects"));
      renameSync(join(a.dir, "Cocoa"), join(a.dir, "Projects/Cocoa"));
      await a.sync();
      await b.sync();
      // The phone as 1.0.5 left it, plus a folder with a note that exists only there.
      mkdirSync(join(b.dir, "Cocoa/sub"), { recursive: true });
      await b.rawWrite("OnlyHere/stray.md", utf8("stray\n"));
      await b.engine.resetToServer();
      expect(existsSync(join(b.dir, "Cocoa"))).toBe(false);
      expect(existsSync(join(b.dir, "OnlyHere"))).toBe(false);
      expect(await b.read("Projects/Cocoa/plan.md")).toBe("plan\n");
      expect(existsSync(join(b.dir, ".trash"))).toBe(true);
    } finally {
      await a.cleanup();
      await b.cleanup();
    }
  });
});
