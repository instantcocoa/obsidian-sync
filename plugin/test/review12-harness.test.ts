/**
 * Twelfth review (2026-11-08): `RemoteServer` in test/ios-harness.ts now runs
 * `sudo systemctl stop/start`, `sudo rm -rf /var/lib/private/obsync` and a
 * `find … -exec rm -rf` on the owner's real server over ssh. These proofs
 * drive the class with a fake `sh`/`healthy` (no ssh, no device) and look at
 * the commands it would send.
 *
 *  D1. restoreFrom(name) deletes the live data BEFORE anything checks that
 *      the backup exists (`rm -rf DATA && cp -a /var/lib/private/<name> DATA`);
 *      a mistyped or vanished name leaves no data and, because `sh` throws
 *      before resume(), a stopped server. Fails on HEAD (1256db0).
 *  D2. `name` is interpolated raw into a remote shell line; an empty name
 *      copies ALL of /var/lib/private over the data dir, and nothing checks
 *      the shape the harness itself produces (`obsync-backup-<digits>`).
 *      Fails on HEAD.
 *  D3. backup(), restoreFrom() and wipe() all halt first and resume last with
 *      no try/finally: when the middle command fails the server stays down.
 *      Fails on HEAD.
 */
import { describe, expect, it } from "vitest";
import { RemoteServer } from "./ios-harness";

/** RemoteServer with the ssh and /healthz legs replaced: records commands, tracks stop/start, fails on demand. */
class FakeRemote extends RemoteServer {
  cmds: string[] = [];
  up = true;
  fail: RegExp | null = null;
  constructor() {
    super("https://example.invalid", "nowhere", "ad_none");
  }
  override sh(cmd: string): string {
    this.cmds.push(cmd);
    if (/systemctl stop obsync/.test(cmd)) this.up = false;
    if (this.fail?.test(cmd)) throw new Error(`ssh nowhere: ${cmd}: exit 1`);
    if (/systemctl start obsync/.test(cmd)) this.up = true;
    return "";
  }
  override async healthy(): Promise<boolean> {
    return this.up;
  }
}

const DATA = "/var/lib/private/obsync";

describe("D1. restoreFrom deletes the live data before the backup is known to exist", () => {
  it("a missing backup name: the data is gone and the server is left stopped", async () => {
    const r = new FakeRemote();
    r.fail = /cp -a/; // the source does not exist: cp fails
    await r.restoreFrom("obsync-backup-1").catch(() => undefined);
    const restore = r.cmds.find((c) => /rm -rf/.test(c)) ?? "";
    // The deletion must not be the first thing on the line; the source must
    // be checked (or the old data moved aside) before anything is removed.
    expect(restore, `the restore line removes ${DATA} before anything proves the backup exists: ${restore}`).not.toMatch(new RegExp(`^\\s*sudo rm -rf ${DATA.replace(/\//g, "\\/")}\\s*&&`));
    expect(r.up, `commands sent: ${JSON.stringify(r.cmds)}; the owner's server is left stopped`).toBe(true);
  });
});

describe("D2. the backup name is trusted as a shell word", () => {
  for (const bad of ["", "undefined", "../..", "x; sudo reboot", "obsync-backup-1 /etc"]) {
    it(`restoreFrom(${JSON.stringify(bad)}) sends no destructive command`, async () => {
      const r = new FakeRemote();
      await r.restoreFrom(bad).catch(() => undefined);
      const destructive = r.cmds.filter((c) => /rm -rf|cp -a/.test(c));
      expect(destructive, `sent over ssh for name ${JSON.stringify(bad)}: ${JSON.stringify(destructive)}`).toEqual([]);
    });
  }
});

describe("D3. a failure between halt and resume leaves the real server stopped", () => {
  it("backup: cp fails", async () => {
    const r = new FakeRemote();
    r.fail = /cp -a/;
    await r.backup().catch(() => undefined);
    expect(r.up, JSON.stringify(r.cmds)).toBe(true);
  });
  it("wipe: the find fails (e.g. `cd /var/lib/private/obsync` is refused to the ssh user: the directory is root 0700 under DynamicUser)", async () => {
    const r = new FakeRemote();
    r.fail = /find/;
    await r.wipe().catch(() => undefined);
    expect(r.up, JSON.stringify(r.cmds)).toBe(true);
  });
});
