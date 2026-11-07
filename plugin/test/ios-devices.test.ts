/**
 * The shipped plugin inside real Obsidian for iOS, on a physical iPhone and
 * iPad plugged into this Mac, against the server on a real host over HTTPS.
 * The third device is "a desktop": a Node engine on the Mac. Devices are
 * driven through Xcode's devicectl (see ios-harness.ts): files in and out of
 * Obsidian's container, launch and force-quit by bundle id, in-app edits
 * through `obsidian://new`, screenshots for evidence under .cache/ios/.
 *
 * One pass, in order: join over HTTPS, content both ways, an edit made
 * while the app was closed, three-way conflict on a fresh note, three-way
 * clean merge, delete and rename, server outage, force quit mid-download,
 * backgrounding, non-ASCII and NFD names, config sync, server restored from
 * a backup, device removal with key rotation and re-join, a synced plugin,
 * and a final byte-for-byte convergence check across all three.
 *
 * Needs, on the device: Obsidian installed, Developer Mode on, a vault named
 * $IOS_VAULT (default "obsync") opened once so Obsidian reopens it on
 * launch. Everything else is pushed in. Run:
 *
 *   IOS_DEVICES=1 IOS_SERVER=https://util.frob.io IOS_SERVER_HOST=util IOS_ADMIN=ad_… \
 *   IOS_IPHONE=<udid or name> IOS_IPAD=<udid or name> npx vitest run test/ios-devices.test.ts
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Device } from "./harness";
import { IosDevice, RemoteServer, sleep, waitFor } from "./ios-harness";
import { createVault, createInviteLink, joinWithLink, listDevices, removeDevice, type Session } from "../src/core/admin";
import { CONFLICT_RE } from "../src/core/paths";
import { randomBytes as nodeRandom } from "node:crypto";

const ON = process.env.IOS_DEVICES === "1";
const ROOT = resolve(__dirname, "..");
const T = 600_000;

function log(msg: string): void {
  console.log(`[${new Date().toISOString().slice(11, 19)}] ${msg}`);
}

/** data.json for a device whose identity was enrolled here, plus what makes Obsidian load the plugin. */
function stage(session: Session, deviceName: string): string {
  const dir = mkdtempSync(join(tmpdir(), `ios-stage-${deviceName}-`));
  mkdirSync(join(dir, ".obsidian/plugins/obsync"), { recursive: true });
  for (const f of ["main.js", "manifest.json", "styles.css"]) copyFileSync(join(ROOT, f), join(dir, ".obsidian/plugins/obsync", f));
  writeFileSync(join(dir, ".obsidian/plugins/obsync/data.json"), JSON.stringify({ identity: session.identity, deviceName }, null, 2));
  writeFileSync(join(dir, ".obsidian/community-plugins.json"), JSON.stringify(["obsync"]));
  writeFileSync(join(dir, ".obsidian/app.json"), JSON.stringify({ legacyEditor: false, safeMode: false }));
  return dir;
}

describe.skipIf(!ON)("obsync on a physical iPhone and iPad (real Obsidian for iOS, HTTPS server on a real host)", () => {
  const url = process.env.IOS_SERVER!;
  const admin = process.env.IOS_ADMIN!;
  const vaultName = process.env.IOS_VAULT ?? "obsync";
  let srv: RemoteServer;
  let mac: Device;
  let macS: Session;
  let phone: IosDevice;
  let pad: IosDevice;
  let padS: Session;
  let big: Uint8Array;

  const sameOnAll = async (path: string, want: string | Uint8Array): Promise<boolean> => {
    await mac.sync();
    const w = typeof want === "string" ? new TextEncoder().encode(want) : want;
    const eq = (b: Uint8Array | null) => b !== null && b.length === w.length && Buffer.compare(b, w) === 0;
    if (!(await mac.exists(path)) || !eq(await mac.readBytes(path))) return false;
    if (!eq(await phone.readBytes(path))) return false;
    return eq(await pad.readBytes(path));
  };

  /** Push a freshly enrolled identity and the plugin into the device's vault and start Obsidian. */
  const provision = async (dev: IosDevice, s: Session, opts: { wipe?: boolean } = {}): Promise<void> => {
    dev.kill();
    if (opts.wipe) await dev.wipe();
    const dir = stage(s, dev.name);
    try {
      dev.push(join(dir, ".obsidian"), "");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    dev.launch({ fresh: true });
  };

  beforeAll(async () => {
    for (const k of ["IOS_SERVER", "IOS_SERVER_HOST", "IOS_ADMIN", "IOS_IPHONE", "IOS_IPAD"]) if (!process.env[k]) throw new Error(`${k} not set`);
    srv = new RemoteServer(url, process.env.IOS_SERVER_HOST!, admin);
    if (!(await srv.healthy())) throw new Error(`${url} is not answering`);
    phone = new IosDevice("iphone", process.env.IOS_IPHONE!, vaultName);
    pad = new IosDevice("ipad", process.env.IOS_IPAD!, vaultName);

    macS = await createVault(url, admin, "mac");
    mac = await new Device("mac", macS).start();
    big = new Uint8Array(nodeRandom(8 * 1024 * 1024));
    await mac.write("notes/hello.md", "# hello from the mac\n");
    await mac.write("attach/big.bin", big);
    await mac.sync();
    log(`vault ${macS.identity.vaultId} seeded from the mac`);

    const phoneS = await joinWithLink(await createInviteLink(macS), "iphone");
    padS = await joinWithLink(await createInviteLink(macS), "ipad");
    await provision(phone, phoneS, { wipe: true });
    await provision(pad, padS, { wipe: true });
    log("plugin, identities and config pushed; Obsidian launched on both devices");
  }, T);

  afterEach(async (ctx) => {
    const label = `${ctx.task.result?.state === "fail" ? "FAIL-" : ""}${ctx.task.name.split(" ").slice(0, 6).join("-")}`;
    phone?.screenshot(label);
    pad?.screenshot(label);
  }, 60_000);

  afterAll(async () => {
    // Leave an invite so another platform (test/linux-joins.test.ts on a Linux box) can join this vault afterwards.
    if (macS) {
      writeFileSync(join(ROOT, ".cache/ios/invite.txt"), await createInviteLink(macS, 6 * 3600));
      // And one for a person's own device (README quick start step 4), valid a day.
      writeFileSync(join(ROOT, ".cache/ios/invite-user.txt"), await createInviteLink(macS, 24 * 3600));
    }
    await mac?.cleanup();
  }, 120_000);

  it("joins over HTTPS and receives the seed, an 8 MB binary included", async () => {
    await waitFor("hello.md on the iPhone", async () => (await phone.read("notes/hello.md")) === "# hello from the mac\n");
    await waitFor("hello.md on the iPad", async () => (await pad.read("notes/hello.md")) === "# hello from the mac\n");
    await waitFor("big.bin on the iPhone", async () => {
      const b = await phone.readBytes("attach/big.bin");
      return b !== null && b.length === big.length && Buffer.compare(b, big) === 0;
    }, 300_000);
    await waitFor("big.bin on the iPad", async () => {
      const b = await pad.readBytes("attach/big.bin");
      return b !== null && b.length === big.length && Buffer.compare(b, big) === 0;
    }, 300_000);
    const roster = await listDevices(macS);
    expect(roster.map((d) => d.name).sort()).toEqual(["ipad", "iphone", "mac"]);
    phone.screenshot("joined");
    pad.screenshot("joined");
    log("both devices joined and hold the seed");
  }, T);

  it("a note typed on the iPhone reaches the iPad and the Mac", async () => {
    phone.newNote("notes/from-phone.md", "# typed on the iphone\n");
    await waitFor("from-phone.md on the mac", async () => {
      await mac.sync();
      return (await mac.exists("notes/from-phone.md")) && /typed on the iphone/.test(await mac.read("notes/from-phone.md"));
    });
    await waitFor("from-phone.md on the iPad", async () => /typed on the iphone/.test((await pad.read("notes/from-phone.md")) ?? ""));
    log("in-app edit on the iPhone propagated");
  }, T);

  it("an edit made while the iPad app was closed syncs on the next launch", async () => {
    pad.kill();
    await pad.write("notes/offline-pad.md", "# written while obsidian was closed on the ipad\n");
    pad.launch();
    await waitFor("offline-pad.md on the mac", async () => {
      await mac.sync();
      return mac.exists("notes/offline-pad.md");
    });
    await waitFor("offline-pad.md on the iPhone", () => phone.exists("notes/offline-pad.md"));
    log("closed-app edit on the iPad propagated on launch");
  }, T);

  it("the same new note written on all three at once ends in one head plus conflict copies, nothing lost", async () => {
    phone.kill();
    pad.kill();
    await mac.write("notes/shared.md", "mac version\n");
    await phone.write("notes/shared.md", "phone version\n");
    await pad.write("notes/shared.md", "pad version\n");
    await mac.sync();
    phone.launch();
    pad.launch();
    const versions = await waitFor("three versions of shared.md on the mac", async () => {
      await mac.sync();
      const fs = (await mac.files()).filter((p) => p === "notes/shared.md" || (p.startsWith("notes/shared (conflict") && CONFLICT_RE.test(p)));
      if (fs.length < 3) return null;
      const texts = await Promise.all(fs.map((p) => mac.read(p)));
      return texts.sort();
    }, 240_000);
    expect(versions).toEqual(["mac version\n", "pad version\n", "phone version\n"]);
    const macFiles = (await mac.files()).filter((p) => p.startsWith("notes/shared"));
    expect(macFiles).toHaveLength(3);
    await waitFor("the same three files on the iPhone", async () => {
      const fs = (await phone.files()).filter((p) => p.startsWith("notes/shared"));
      return fs.length === 3 && fs.every((p) => macFiles.includes(p));
    }, 240_000);
    await waitFor("the same three files on the iPad", async () => {
      const fs = (await pad.files()).filter((p) => p.startsWith("notes/shared"));
      return fs.length === 3 && fs.every((p) => macFiles.includes(p));
    }, 240_000);
    log(`three-way conflict resolved as: ${macFiles.join(" | ")}`);
  }, T);

  it("a note edited in different paragraphs on all three merges cleanly, no conflict copy", async () => {
    const base = "# plan\n\nfirst paragraph\n\nsecond paragraph\n\nthird paragraph\n";
    await mac.write("notes/plan.md", base);
    await waitFor("plan.md everywhere", () => sameOnAll("notes/plan.md", base));
    phone.kill();
    pad.kill();
    await mac.write("notes/plan.md", base.replace("first paragraph", "first paragraph (mac)"));
    await phone.write("notes/plan.md", base.replace("second paragraph", "second paragraph (phone)"));
    await pad.write("notes/plan.md", base.replace("third paragraph", "third paragraph (pad)"));
    await mac.sync();
    phone.launch();
    pad.launch();
    const merged = "# plan\n\nfirst paragraph (mac)\n\nsecond paragraph (phone)\n\nthird paragraph (pad)\n";
    await waitFor("merged plan.md on all three", () => sameOnAll("notes/plan.md", merged), 300_000);
    const copies = (await mac.files()).filter((p) => p.startsWith("notes/plan (conflict"));
    expect(copies).toEqual([]);
    log("three-way edit merged line by line on every device");
  }, T);

  it("delete and rename on the Mac apply on both devices", async () => {
    await mac.remove("notes/hello.md");
    await mac.write("notes/renamed-from-phone.md", await mac.read("notes/from-phone.md"));
    await mac.remove("notes/from-phone.md");
    await mac.sync();
    for (const d of [phone, pad]) {
      await waitFor(`delete and rename on the ${d.name}`, async () => !(await d.exists("notes/hello.md")) && !(await d.exists("notes/from-phone.md")) && (await d.exists("notes/renamed-from-phone.md")));
    }
    log("delete and rename applied on both devices");
  }, T);

  it("an edit on the iPhone while the server is down syncs when it returns", async () => {
    await srv.halt();
    phone.newNote("notes/outage.md", "# written during the outage\n");
    await sleep(15_000);
    phone.screenshot("server-down");
    await srv.resume();
    await waitFor("outage.md on the mac", async () => {
      await mac.sync();
      return mac.exists("notes/outage.md");
    }, 240_000);
    await waitFor("outage.md on the iPad", () => pad.exists("notes/outage.md"), 240_000);
    log("edit made during the outage synced after the server returned");
  }, T);

  it("a force quit right after a large file starts arriving leaves the file intact on relaunch", async () => {
    const big2 = new Uint8Array(nodeRandom(12 * 1024 * 1024));
    await mac.write("attach/big2.bin", big2);
    await mac.sync();
    await sleep(3_000);
    phone.kill();
    await sleep(2_000);
    phone.launch();
    await waitFor("big2.bin intact on the iPhone", async () => {
      const b = await phone.readBytes("attach/big2.bin");
      return b !== null && b.length === big2.length && Buffer.compare(b, big2) === 0;
    }, 300_000);
    await waitFor("big2.bin intact on the iPad", async () => {
      const b = await pad.readBytes("attach/big2.bin");
      return b !== null && b.length === big2.length && Buffer.compare(b, big2) === 0;
    }, 300_000);
    log("12 MB file intact after a force quit during download");
  }, T);

  it("a change made while the iPhone app was in the background arrives when it comes back", async () => {
    phone.background();
    await sleep(5_000);
    await mac.write("notes/while-backgrounded.md", "# written while the iphone was in the background\n");
    await mac.sync();
    await sleep(20_000);
    phone.foreground();
    await waitFor("while-backgrounded.md on the iPhone", () => phone.exists("notes/while-backgrounded.md"));
    log("backgrounded iPhone caught up on return");
  }, T);

  it("non-ASCII names, including one written in NFD on the iPad, converge under one spelling", async () => {
    const nfc = "notes/Übersicht/Café résumé.md";
    await mac.write(nfc, "# accents from the mac\n");
    await mac.sync();
    pad.kill();
    await pad.write("notes/Ärger.md".normalize("NFD"), "# nfd name written on the ipad\n");
    pad.launch();
    await waitFor("accented files on the iPhone", async () => {
      const fs = (await phone.files()).map((p) => p.normalize("NFC"));
      return fs.includes(nfc) && fs.includes("notes/Ärger.md");
    });
    await waitFor("NFD-written file on the mac under its NFC name", async () => {
      await mac.sync();
      return (await mac.files()).map((p) => p.normalize("NFC")).includes("notes/Ärger.md");
    });
    const macNames = (await mac.files()).filter((p) => p.normalize("NFC") === "notes/Ärger.md");
    expect(macNames).toHaveLength(1);
    log("non-ASCII and NFD names converged");
  }, T);

  it("a config change from the Mac lands in both devices' .obsidian", async () => {
    const current = await waitFor("app.json from a device on the mac", async () => {
      await mac.sync();
      return (await mac.exists(".obsidian/app.json")) ? await mac.read(".obsidian/app.json") : null;
    });
    const next = JSON.stringify({ ...(JSON.parse(current) as object), obsyncIosMarker: Date.now() });
    await mac.write(".obsidian/app.json", next);
    await mac.sync();
    for (const d of [phone, pad]) {
      await waitFor(`app.json marker on the ${d.name}`, async () => /obsyncIosMarker/.test((await d.read(".obsidian/app.json")) ?? ""));
    }
    log("config change applied on both devices");
  }, T);

  it("after the server is restored from a backup, every device notices and nothing written since is lost", async () => {
    const bak = await srv.backup();
    phone.newNote("notes/after-backup-phone.md", "# phone note the backup does not have\n");
    await mac.write("notes/after-backup-mac.md", "# mac note the backup does not have\n");
    await mac.sync();
    for (const p of ["notes/after-backup-phone.md", "notes/after-backup-mac.md"]) {
      await waitFor(`${p} everywhere before the restore`, async () => {
        await mac.sync();
        return (await mac.exists(p)) && (await phone.exists(p)) && (await pad.exists(p));
      }, 240_000);
    }
    await srv.restoreFrom(bak);
    log("server restored from the backup taken before those two notes");
    await waitFor("mac recovered from the rewind", async () => {
      await mac.sync();
      return (await mac.exists("notes/after-backup-mac.md")) && (await mac.exists("notes/after-backup-phone.md"));
    }, 240_000);
    for (const d of [phone, pad]) {
      await waitFor(`${d.name} still has both notes after the rewind`, async () => (await d.exists("notes/after-backup-phone.md")) && (await d.exists("notes/after-backup-mac.md")), 300_000);
    }
    await waitFor("no conflict copies from the rewind", async () => {
      await mac.sync();
      return !(await mac.files()).some((p) => p.startsWith("notes/after-backup") && CONFLICT_RE.test(p));
    }, 120_000);
    await mac.write("notes/after-restore.md", "# written after the restore\n");
    await mac.sync();
    for (const d of [phone, pad]) await waitFor(`after-restore.md on the ${d.name}`, () => d.exists("notes/after-restore.md"), 240_000);
    log("all three devices recovered from the restored server without loss or duplicates");
  }, T);

  it("removing the iPad rotates the keys: it stops receiving, the iPhone continues, and a new invite brings it back", async () => {
    const padId = (await listDevices(macS)).find((d) => d.name === "ipad")!.id;
    await removeDevice(macS, padId);
    await mac.write("notes/after-rotation.md", "# only devices with the new keys see this\n");
    await mac.sync();
    await waitFor("after-rotation.md on the iPhone", () => phone.exists("notes/after-rotation.md"), 240_000);
    await sleep(45_000);
    expect(await pad.exists("notes/after-rotation.md")).toBe(false);
    pad.screenshot("removed");
    log("removed iPad received nothing after the rotation; iPhone did");
    padS = await joinWithLink(await createInviteLink(macS), "ipad");
    await provision(pad, padS);
    await waitFor("after-rotation.md on the re-joined iPad", () => pad.exists("notes/after-rotation.md"), 300_000);
    log("iPad re-joined with a new invite and caught up");
  }, T);

  it("a community plugin added on the Mac is delivered to the iPhone", async () => {
    await mac.write(".obsidian/plugins/obsync-demo/manifest.json", JSON.stringify({ id: "obsync-demo", name: "obsync demo", version: "0.0.1", minAppVersion: "1.4.0", description: "sync test", author: "obsync", isDesktopOnly: false }));
    await mac.write(".obsidian/plugins/obsync-demo/main.js", "const { Plugin } = require('obsidian'); module.exports = class extends Plugin { onload() { this.addCommand({ id: 'obsync-demo-noop', name: 'obsync demo', callback() {} }); } };\n");
    await mac.write(".obsidian/community-plugins.json", JSON.stringify(["obsync", "obsync-demo"]));
    await mac.sync();
    await waitFor("demo plugin on the iPhone", async () => (await phone.exists(".obsidian/plugins/obsync-demo/main.js")) && /obsync-demo/.test((await phone.read(".obsidian/community-plugins.json")) ?? ""), 240_000);
    log("plugin files and the enabled list arrived on the iPhone");
  }, T);

  it("the same line edited in-app on the iPhone and the iPad at the same moment: one head, one conflict copy, both kept", async () => {
    await mac.write("notes/live.md", "line one\n");
    await waitFor("live.md everywhere", () => sameOnAll("notes/live.md", "line one\n"));
    phone.newNote("notes/live.md", "line one (phone)\n");
    pad.newNote("notes/live.md", "line one (pad)\n");
    const versions = await waitFor("two versions of live.md on the mac", async () => {
      await mac.sync();
      const fs = (await mac.files()).filter((p) => p === "notes/live.md" || (p.startsWith("notes/live (conflict") && CONFLICT_RE.test(p)));
      if (fs.length < 2) return null;
      return (await Promise.all(fs.map((p) => mac.read(p)))).sort();
    }, 240_000);
    expect(versions).toEqual(["line one (pad)\n", "line one (phone)\n"]);
    const names = (await mac.files()).filter((p) => p.startsWith("notes/live"));
    for (const d of [phone, pad]) {
      await waitFor(`the same live files on the ${d.name}`, async () => {
        const fs = (await d.files()).filter((p) => p.startsWith("notes/live"));
        return fs.length === names.length && fs.every((p) => names.includes(p));
      }, 240_000);
    }
    log(`live same-line conflict: ${names.join(" | ")}`);
  }, T);

  it("renamed on the Mac while the iPad edited it at the old name: both files survive", async () => {
    await mac.write("notes/r.md", "# r\n");
    await waitFor("r.md everywhere", () => sameOnAll("notes/r.md", "# r\n"));
    pad.kill();
    await pad.write("notes/r.md", "# r edited on the ipad\n");
    await mac.write("notes/r-renamed.md", "# r\n");
    await mac.remove("notes/r.md");
    await mac.sync();
    pad.launch();
    await waitFor("rename and edit both present everywhere", async () => {
      await mac.sync();
      for (const d of [phone, pad]) {
        if ((await d.read("notes/r-renamed.md")) !== "# r\n") return false;
        if ((await d.read("notes/r.md")) !== "# r edited on the ipad\n") return false;
      }
      return (await mac.read("notes/r-renamed.md")) === "# r\n" && (await mac.read("notes/r.md")) === "# r edited on the ipad\n";
    }, 240_000);
    log("rename vs edit: both files present on all three");
  }, T);

  it("a binary edited on the iPhone and the iPad at once: head and conflict copy both bit-exact", async () => {
    const base = new Uint8Array(nodeRandom(1024 * 1024));
    await mac.write("attach/pic.bin", base);
    await waitFor("pic.bin everywhere", () => sameOnAll("attach/pic.bin", base), 240_000);
    phone.kill();
    pad.kill();
    const vPhone = new Uint8Array(nodeRandom(1024 * 1024));
    const vPad = new Uint8Array(nodeRandom(1024 * 1024));
    await phone.write("attach/pic.bin", vPhone);
    await pad.write("attach/pic.bin", vPad);
    phone.launch();
    pad.launch();
    const names = await waitFor("two pic.bin versions on the mac, bit-exact", async () => {
      await mac.sync();
      const fs = (await mac.files()).filter((p) => p === "attach/pic.bin" || p.startsWith("attach/pic (conflict"));
      if (fs.length < 2) return null;
      const bytes = await Promise.all(fs.map((p) => mac.readBytes(p)));
      const has = (v: Uint8Array) => bytes.some((b) => b.length === v.length && Buffer.compare(b, v) === 0);
      return has(vPhone) && has(vPad) ? fs : null;
    }, 300_000);
    for (const d of [phone, pad]) {
      await waitFor(`both pic versions on the ${d.name}`, async () => {
        for (const n of names) {
          const b = await d.readBytes(n);
          if (!b || !(Buffer.compare(b, vPhone) === 0 || Buffer.compare(b, vPad) === 0)) return false;
        }
        return true;
      }, 300_000);
    }
    log(`binary conflict: ${names.join(" | ")}`);
  }, T);

  it("a folder deleted on the Mac while the iPhone edited a note inside it: the edited note survives, the rest goes", async () => {
    await mac.write("notes/proj/a.md", "# a\n");
    await mac.write("notes/proj/b.md", "# b\n");
    await waitFor("proj everywhere", async () => (await sameOnAll("notes/proj/a.md", "# a\n")) && (await sameOnAll("notes/proj/b.md", "# b\n")));
    phone.kill();
    await phone.write("notes/proj/a.md", "# a edited on the iphone\n");
    await mac.remove("notes/proj/a.md");
    await mac.remove("notes/proj/b.md");
    await mac.sync();
    phone.launch();
    await waitFor("a.md back everywhere, b.md gone everywhere", async () => {
      await mac.sync();
      if ((await mac.read("notes/proj/a.md").catch(() => null)) !== "# a edited on the iphone\n" || (await mac.exists("notes/proj/b.md"))) return false;
      for (const d of [phone, pad]) if ((await d.read("notes/proj/a.md")) !== "# a edited on the iphone\n" || (await d.exists("notes/proj/b.md"))) return false;
      return true;
    }, 240_000);
    log("folder delete vs edit inside: edited note survived, sibling note deleted");
  }, T);

  it("ten rapid alternating in-app edits from the iPhone and the iPad lose nothing", async () => {
    await mac.write("notes/rapid.md", "# rapid\n");
    await waitFor("rapid.md everywhere", () => sameOnAll("notes/rapid.md", "# rapid\n"));
    for (let i = 0; i < 5; i++) {
      phone.appendNote("notes/rapid.md", `phone-${i}`);
      pad.appendNote("notes/rapid.md", `pad-${i}`);
    }
    const markers = [...Array(5).keys()].flatMap((i) => [`phone-${i}`, `pad-${i}`]);
    const names = await waitFor("every appended line present on the mac across head and copies", async () => {
      await mac.sync();
      const fs = (await mac.files()).filter((p) => p === "notes/rapid.md" || p.startsWith("notes/rapid (conflict"));
      const text = (await Promise.all(fs.map((p) => mac.read(p)))).join("\n");
      return markers.every((m) => text.includes(m)) ? fs : null;
    }, 300_000);
    for (const d of [phone, pad]) {
      await waitFor(`the same rapid files on the ${d.name}`, async () => {
        const fs = (await d.files()).filter((p) => p.startsWith("notes/rapid"));
        if (fs.length !== names.length || !fs.every((p) => names.includes(p))) return false;
        const text = (await Promise.all(fs.map((p) => d.read(p)))).join("\n");
        return markers.every((m) => text.includes(m));
      }, 300_000);
    }
    log(`rapid alternating edits: ${names.length} file(s): ${names.join(" | ")}`);
  }, T);

  it("all three devices hold the same files byte for byte", async () => {
    const skip = (p: string) => p.startsWith(".obsidian/") || p.startsWith(".trash/");
    let last = "";
    try {
      await waitFor("identical file lists", async () => {
        await mac.sync();
        // Sort after normalising: an NFD "A\u0308" sorts before "a", its NFC "Ä" after "z".
        const norm = (fs: string[]) => fs.filter((p) => !skip(p)).map((p) => p.normalize("NFC")).sort();
        const m = norm(await mac.files());
        const ph = norm(await phone.files());
        const pd = norm(await pad.files());
        const only = (a: string[], b: string[]) => a.filter((x) => !b.includes(x));
        last = `mac-only=${JSON.stringify(only(m, ph))} phone-only=${JSON.stringify(only(ph, m))} pad-only-vs-mac=${JSON.stringify(only(pd, m))} mac-only-vs-pad=${JSON.stringify(only(m, pd))}`;
        return JSON.stringify(m) === JSON.stringify(ph) && JSON.stringify(m) === JSON.stringify(pd) ? m : null;
      }, 300_000);
    } catch (e) {
      throw new Error(`${(e as Error).message}\n${last}`);
    }
    const files = (await mac.files()).filter((p) => !skip(p));
    for (const p of files) {
      const want = await mac.readBytes(p);
      for (const d of [phone, pad]) {
        const got = await d.readBytes(p);
        expect(got !== null && Buffer.compare(got, want) === 0, `${p} on the ${d.name}`).toBe(true);
      }
    }
    log(`${files.length} files identical on the mac, the iPhone and the iPad`);
  }, T);
});
