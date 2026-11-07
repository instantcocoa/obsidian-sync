/**
 * Real Obsidian on Linux joining a vault that other platforms already share:
 * the vault the iOS device run (test/ios-devices.test.ts) leaves behind on a
 * real server. The iOS run writes an invite link to .cache/ios/invite.txt;
 * this test, run on a Linux box with Obsidian under Xvfb, pastes it into the
 * plugin's settings tab, waits for the iPhone-and-iPad vault to arrive,
 * checks a note the three other devices merged, writes one of its own, and
 * leaves screenshots of the Obsidian window for the catalog.
 *
 * Whether the devices received the Linux note is checked from the Mac
 * afterwards (pull notes/from-linux.md from both), since the devices hang off
 * the Mac, not this box.
 *
 *   OBSIDIAN_BIN=~/obsidian/squashfs-root/obsidian XVFB_RUN=xvfb-run \
 *   OBSYNC_INVITE='obsync://join#…' [SHOTS_DIR=~/obsync/shots] npx vitest run test/linux-joins.test.ts
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { ObsidianInstance, OBSIDIAN_BIN } from "./obsidian-harness";

const LINK = process.env.OBSYNC_INVITE ?? "";
const ON = process.platform === "linux" && Boolean(OBSIDIAN_BIN) && LINK.startsWith("obsync://join#");
const SHOTS = process.env.SHOTS_DIR ?? join(__dirname, "..", ".cache", "linux");

function shotName(label: string): string {
  const ts = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
  return join(SHOTS, `${ts}-linux-${label}.png`);
}

describe.skipIf(!ON)("real Obsidian on Linux joins the vault the iPhone and iPad share", () => {
  let o: ObsidianInstance;
  beforeAll(async () => {
    mkdirSync(SHOTS, { recursive: true });
    o = await ObsidianInstance.launch("linux");
  }, 180_000);
  afterAll(async () => {
    await o?.page.screenshot({ path: shotName("final") }).catch(() => {});
    await o?.stop();
  });

  it("joins with the invite the iOS run left and receives the shared vault", async () => {
    await o.openSettings();
    await o.fill("obsync://join#…", LINK);
    await o.clickButton("Join");
    const joined = await o.waitFor(() => Boolean((globalThis as any).app.plugins.plugins.obsync.settings.identity), 30_000);
    if (!joined) throw new Error(`join failed\n${await o.diagnostics()}`);
    await o.closeSettings();
    // plan.md is the note the Mac, the iPhone and the iPad each edited in a different paragraph; it must arrive merged.
    const merged = "# plan\n\nfirst paragraph (mac)\n\nsecond paragraph (phone)\n\nthird paragraph (pad)\n";
    expect(await o.waitForFile("notes/plan.md", merged, 120_000)).not.toBeNull();
    expect(await o.waitForFile("notes/offline-pad.md", undefined, 60_000)).not.toBeNull();
    await o.page.screenshot({ path: shotName("joined") });
    console.log(`[${new Date().toISOString().slice(11, 19)}] Linux Obsidian joined and holds the shared vault`);
  }, 300_000);

  it("the conflict copies and the 12 MB attachment from the device run are present", async () => {
    const files = await o.eval((_p, app) => app.vault.getFiles().map((f: { path: string }) => f.path).sort());
    const shared = files.filter((p: string) => p.startsWith("notes/shared"));
    expect(shared.length).toBe(3);
    const big = await o.eval((_p, app) => app.vault.getAbstractFileByPath("attach/big2.bin")?.stat?.size ?? 0);
    expect(big).toBe(12 * 1024 * 1024);
    console.log(`[${new Date().toISOString().slice(11, 19)}] ${files.length} files; conflict copies: ${shared.join(", ")}`);
  }, 120_000);

  it("a note written in Obsidian on Linux is pushed to the server", async () => {
    await o.eval((_p, app) => app.vault.create("notes/from-linux.md", "# written in Obsidian on Linux\n"));
    const pushed = await o.waitFor(() => {
      const st = (globalThis as any).app.plugins.plugins.obsync.engine?.getStatus?.();
      return st && st.phase !== "error" && st.phase !== "offline" && !st.pending;
    }, 60_000);
    expect(pushed).toBe(true);
    await o.page.screenshot({ path: shotName("wrote-note") });
    console.log(`[${new Date().toISOString().slice(11, 19)}] from-linux.md written and the engine is idle`);
  }, 120_000);
});
